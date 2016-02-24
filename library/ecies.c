/**
 * Copyright (C) 2015 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of extension to mbed TLS (https://tls.mbed.org)
 */
/**
 * Implementation is based on the standard ISO 18033-2.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECIES_C)

#include "mbedtls/ecies.h"
#include "mbedtls/ecies_envelope.h"

#include "mbedtls/cipher.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"
#include "mbedtls/kdf.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#define INVOKE_AND_CHECK(result,invocation) \
    if ((result = invocation) < 0) goto exit;

#define ACCUMULATE_AND_CHECK(result, len, invocation) \
do { \
    if ((result = invocation) < 0) { \
        goto exit; \
    } else { \
        len += result; \
        result = 0; \
    } \
} while (0)

#define ECIES_OCTET_SIZE 8
#define ECIES_SIZE_TO_OCTETS(size) ((size + 7) / ECIES_OCTET_SIZE)

#define ECIES_ENVELOPE_VERSION 0

static int ecies_ka(mbedtls_ecp_keypair *public, const mbedtls_ecp_keypair *private,
        mbedtls_mpi *shared, int(*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (public == NULL || private == NULL || shared == NULL) {
        return MBEDTLS_ERR_ECIES_BAD_INPUT_DATA;
    }
    if (public->grp.id != private->grp.id) {
        return MBEDTLS_ERR_ECIES_BAD_INPUT_DATA;
    }
    return mbedtls_ecdh_compute_shared(&public->grp, shared, &public->Q, &private->d,
            f_rng, p_rng);
}

int mbedtls_ecies_encrypt(mbedtls_ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int result = 0;
    mbedtls_ecp_keypair ephemeral_key;
    mbedtls_mpi shared_key;
    unsigned char *shared_key_binary = NULL; // MUST be released
    size_t shared_key_binary_len = 0;
    const mbedtls_md_info_t *md_info = NULL;
    const mbedtls_kdf_info_t *kdf_info = NULL;
    const mbedtls_md_info_t *hmac_info = NULL;
    unsigned char *kdf_value = NULL; // MUST be released
    size_t hmac_len = 0;
    unsigned char *hmac = NULL; // MUST be released
    size_t kdf_len = 0;
    unsigned char *cipher_key = NULL; // pointer inside data: kdf_value
    size_t cipher_key_len = 0;
    unsigned char *cipher_iv = NULL; // MUST be released
    size_t cipher_iv_len = 0;
    unsigned char *hmac_key = NULL; // pointer inside data: kdf_value
    size_t hmac_key_len = 0;
    mbedtls_cipher_context_t cipher_ctx;
    size_t cipher_block_size = 0;
    size_t cipher_enc_data_len = 0;
    size_t cipher_enc_header_len = 0;
    unsigned char *cipher_enc_data = NULL; // pointer inside data: output

    if (key == NULL || input == NULL || output == NULL || olen == NULL) {
        return MBEDTLS_ERR_ECIES_BAD_INPUT_DATA;
    }

    // Init structures.
    *olen = 0;

    md_info = mbedtls_md_info_from_type(MBEDTLS_ECIES_MD_TYPE);
    kdf_info = mbedtls_kdf_info_from_type(MBEDTLS_ECIES_KDF_TYPE);
    hmac_info = mbedtls_md_info_from_type(MBEDTLS_ECIES_HMAC_TYPE);

    mbedtls_mpi_init(&shared_key);
    mbedtls_ecp_keypair_init(&ephemeral_key);
    mbedtls_cipher_init(&cipher_ctx);
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_ECIES_CIPHER_TYPE))
    );

    cipher_iv_len = mbedtls_cipher_get_iv_size(&cipher_ctx);
    cipher_key_len = ECIES_SIZE_TO_OCTETS(mbedtls_cipher_get_key_bitlen(&cipher_ctx));
    hmac_len = mbedtls_md_get_size(hmac_info);
    hmac_key_len = hmac_len;
    kdf_len = cipher_key_len + hmac_key_len;

    kdf_value = mbedtls_calloc(1, kdf_len);
    if (kdf_value == NULL) {
        INVOKE_AND_CHECK(result, MBEDTLS_ERR_ECIES_ALLOC_FAILED)
    }

    cipher_key = kdf_value;
    hmac_key = kdf_value + cipher_key_len;

    // 1. Generate ephemeral keypair.
    INVOKE_AND_CHECK(result,
        mbedtls_ecp_gen_key(key->grp.id, &ephemeral_key, f_rng, p_rng)
    );
    // 2. Compute shared secret key.
    INVOKE_AND_CHECK(result,
        ecies_ka(key, &ephemeral_key, &shared_key, f_rng, p_rng)
    );
    shared_key_binary_len = ECIES_SIZE_TO_OCTETS(key->grp.pbits);
    shared_key_binary = mbedtls_calloc(1, shared_key_binary_len);
    if (shared_key_binary == NULL) {
        INVOKE_AND_CHECK(result, MBEDTLS_ERR_ECIES_ALLOC_FAILED)
    }
    INVOKE_AND_CHECK(result,
        mbedtls_mpi_write_binary(&shared_key, shared_key_binary, shared_key_binary_len)
    );
    // 3. Derive keys (encryption key and hmac key).
    INVOKE_AND_CHECK(result,
        mbedtls_kdf(kdf_info, md_info, shared_key_binary, shared_key_binary_len,
                kdf_value, kdf_len)
    );
    // 4. Encrypt given message.
    cipher_iv = mbedtls_calloc(1, cipher_iv_len);
    if (cipher_iv == NULL) {
        INVOKE_AND_CHECK(result, MBEDTLS_ERR_ECIES_ALLOC_FAILED)
    }
    INVOKE_AND_CHECK(result,
        f_rng(p_rng, cipher_iv, cipher_iv_len)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_setkey(&cipher_ctx, cipher_key,
                cipher_key_len * ECIES_OCTET_SIZE, MBEDTLS_ENCRYPT)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_set_padding_mode(&cipher_ctx, MBEDTLS_ECIES_CIPHER_PADDING)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_reset(&cipher_ctx)
    );
    cipher_block_size = mbedtls_cipher_get_block_size(&cipher_ctx);
    cipher_enc_data_len = ilen + cipher_block_size;
    if (osize < cipher_enc_data_len) {
        result = MBEDTLS_ERR_ECIES_OUTPUT_TOO_SMALL;
        goto exit;
    }
    cipher_enc_data = output + osize - cipher_enc_data_len;
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_crypt(&cipher_ctx, cipher_iv, cipher_iv_len, input, ilen,
                cipher_enc_data, &cipher_enc_data_len)
    );
    // 5. Get HMAC for encrypted message.
    hmac = mbedtls_calloc(1, hmac_len);
    if (hmac == NULL) {
        INVOKE_AND_CHECK(result, MBEDTLS_ERR_ECIES_ALLOC_FAILED)
    }
    INVOKE_AND_CHECK(result,
        mbedtls_md_hmac(hmac_info, hmac_key, hmac_key_len,
                cipher_enc_data, cipher_enc_data_len, hmac)
    );
    // 6. Write envelope.
    cipher_enc_header_len = 0;
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        mbedtls_ecies_write_content_info(&cipher_enc_data, output, MBEDTLS_ECIES_CIPHER_TYPE,
                cipher_iv, cipher_iv_len, cipher_enc_data_len)
    );
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        mbedtls_ecies_write_hmac(&cipher_enc_data, output, mbedtls_md_get_type(hmac_info),
                hmac, hmac_len)
    );
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        mbedtls_ecies_write_kdf(&cipher_enc_data, output, mbedtls_kdf_get_type(kdf_info),
                mbedtls_md_get_type(md_info))
    );
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        mbedtls_ecies_write_originator(&cipher_enc_data, output, &ephemeral_key)
    );
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        mbedtls_ecies_write_version(&cipher_enc_data, output, ECIES_ENVELOPE_VERSION)
    );
    ACCUMULATE_AND_CHECK(result, cipher_enc_header_len,
        mbedtls_ecies_write_envelope(&cipher_enc_data, output, cipher_enc_header_len)
    );
    memmove(output, cipher_enc_data, cipher_enc_header_len);
    memset(output + cipher_enc_header_len, 0, osize - cipher_enc_header_len);
exit:
    *olen = cipher_enc_header_len;
    mbedtls_cipher_free(&cipher_ctx);
    mbedtls_ecp_keypair_free(&ephemeral_key);
    mbedtls_mpi_free(&shared_key);
    if (shared_key_binary != NULL) {
        mbedtls_free(shared_key_binary);
    }
    if (kdf_value != NULL) {
        mbedtls_free(kdf_value);
    }
    if (cipher_iv != NULL) {
        mbedtls_free(cipher_iv);
    }
    if (hmac != NULL) {
        mbedtls_free(hmac);
    }
    return result;
}


int mbedtls_ecies_decrypt(mbedtls_ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int result = 0;
    int version = 0;
    mbedtls_ecp_keypair *ephemeral_key = NULL; // MUST be released
    mbedtls_mpi shared_key;
    unsigned char *shared_key_binary = NULL; // MUST be released
    size_t shared_key_binary_len = 0;
    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    mbedtls_kdf_type_t kdf_type = MBEDTLS_KDF_NONE;
    mbedtls_md_type_t hmac_type = MBEDTLS_MD_NONE;
    unsigned char *kdf_value = NULL; // MUST be released
    size_t hmac_base_len = 0;
    unsigned char *hmac_base = NULL; // pointer inside data: input
    size_t hmac_len = 0;
    unsigned char *hmac = NULL; // MUST be released
    size_t kdf_len = 0;
    unsigned char *cipher_key = NULL; // pointer inside data: kdf_value
    size_t cipher_key_len = 0;
    unsigned char *hmac_key = NULL; // pointer inside data: kdf_value
    size_t hmac_key_len = 0;
    unsigned char *cipher_iv = NULL; // pointer inside data: input
    size_t cipher_iv_len = 0;
    mbedtls_cipher_type_t cipher_type = MBEDTLS_CIPHER_NONE;
    mbedtls_cipher_context_t cipher_ctx;
    size_t cipher_enc_data_len = 0;
    size_t cipher_enc_header_len = 0;
    unsigned char *cipher_enc_data = NULL; // pointer inside data: input
    unsigned char *cipher_enc_header = NULL; // pointer inside data: input

    if (key == NULL || input == NULL || output == NULL || olen == NULL) {
        return MBEDTLS_ERR_ECIES_BAD_INPUT_DATA;
    }

    // Init structures.
    *olen = 0;
    mbedtls_cipher_init(&cipher_ctx);
    mbedtls_mpi_init(&shared_key);
    cipher_enc_header = (unsigned char *)input;
    INVOKE_AND_CHECK(result,
        mbedtls_ecies_read_envelope(&cipher_enc_header, input + ilen,
                &cipher_enc_header_len)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_ecies_read_version(&cipher_enc_header, input + ilen, &version)
    );
    if (version != ECIES_ENVELOPE_VERSION) {
        result = MBEDTLS_ERR_ECIES_MALFORMED_DATA;
        goto exit;
    }
    INVOKE_AND_CHECK(result,
        mbedtls_ecies_read_originator(&cipher_enc_header, input + ilen, &ephemeral_key)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_ecies_read_kdf(&cipher_enc_header, input + ilen, &kdf_type, &md_type)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_ecies_read_hmac(&cipher_enc_header, input + ilen, &hmac_type,
                &hmac_base, &hmac_base_len)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_ecies_read_content_info(&cipher_enc_header, input + ilen, &cipher_type,
                &cipher_iv, &cipher_iv_len, &cipher_enc_data,
                &cipher_enc_data_len)
    );

    INVOKE_AND_CHECK(result,
        mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(cipher_type))
    );
    cipher_key_len = ECIES_SIZE_TO_OCTETS(mbedtls_cipher_get_key_bitlen(&cipher_ctx));
    hmac_len = mbedtls_md_get_size(mbedtls_md_info_from_type(hmac_type));
    hmac_key_len = hmac_len;
    kdf_len = cipher_key_len + hmac_key_len;
    kdf_value = mbedtls_calloc(1, kdf_len);
    if (kdf_value == NULL) {
        INVOKE_AND_CHECK(result, MBEDTLS_ERR_ECIES_ALLOC_FAILED)
    }
    cipher_key = kdf_value;
    hmac_key = kdf_value + cipher_key_len;
    hmac = mbedtls_calloc(1, hmac_len);
    if (hmac == NULL) {
        INVOKE_AND_CHECK(result, MBEDTLS_ERR_ECIES_ALLOC_FAILED)
    }

    // 1. Compute shared secret key.
    INVOKE_AND_CHECK(result,
        ecies_ka(ephemeral_key, key, &shared_key, f_rng, p_rng)
    );
    shared_key_binary_len = ECIES_SIZE_TO_OCTETS(key->grp.pbits);
    shared_key_binary = mbedtls_calloc(1, shared_key_binary_len);
    if (shared_key_binary == NULL) {
        INVOKE_AND_CHECK(result, MBEDTLS_ERR_ECIES_ALLOC_FAILED)
    }
    INVOKE_AND_CHECK(result,
        mbedtls_mpi_write_binary(&shared_key, shared_key_binary, shared_key_binary_len)
    );
    // 2. Derive keys (encryption key and hmac key).
    INVOKE_AND_CHECK(result,
        mbedtls_kdf(mbedtls_kdf_info_from_type(kdf_type), mbedtls_md_info_from_type(md_type),
                shared_key_binary, shared_key_binary_len, kdf_value, kdf_len)
    );
    // 3. Get HMAC for encrypted message and compare it.
    INVOKE_AND_CHECK(result,
        mbedtls_md_hmac(mbedtls_md_info_from_type(hmac_type), hmac_key, hmac_key_len,
                cipher_enc_data, cipher_enc_data_len, hmac)
    );
    if (hmac_base_len != hmac_len || memcmp(hmac_base, hmac, hmac_len) != 0) {
        result = MBEDTLS_ERR_ECIES_MALFORMED_DATA;
        goto exit;
    }
    // 4. Decrypt given message.
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_setkey(&cipher_ctx, cipher_key,
                cipher_key_len * ECIES_OCTET_SIZE, MBEDTLS_DECRYPT)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_set_padding_mode(&cipher_ctx, MBEDTLS_ECIES_CIPHER_PADDING)
    );
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_reset(&cipher_ctx)
    );
    if (osize < cipher_enc_data_len) {
        result = MBEDTLS_ERR_ECIES_OUTPUT_TOO_SMALL;
        goto exit;
    }
    INVOKE_AND_CHECK(result,
        mbedtls_cipher_crypt(&cipher_ctx, cipher_iv, cipher_iv_len, cipher_enc_data,
                cipher_enc_data_len, output, olen)
    );
exit:
    mbedtls_cipher_free(&cipher_ctx);
    mbedtls_ecp_keypair_free(ephemeral_key);
    mbedtls_mpi_free(&shared_key);
    if (shared_key_binary != NULL) {
        mbedtls_free(shared_key_binary);
    }
    if (kdf_value != NULL) {
        mbedtls_free(kdf_value);
    }
    if (hmac != NULL) {
        mbedtls_free(hmac);
    }
    return result;
}

#endif /* defined(MBEDTLS_ECIES_C) */
