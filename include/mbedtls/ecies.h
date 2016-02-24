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
#ifndef MBEDTLS_ECIES_H
#define MBEDTLS_ECIES_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined (MBEDTLS_CIPHER_C)
#include "mbedtls/cipher.h"
#endif

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDH_C)
#include "mbedtls/ecdh.h"
#endif

#if defined(MBEDTLS_MD_C)
#include "mbedtls/md.h"
#endif

#if defined(MBEDTLS_KDF_C)
#include "mbedtls/kdf.h"
#endif

#define MBEDTLS_ERR_ECIES_BAD_INPUT_DATA                    -0x4B80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_ECIES_OUTPUT_TOO_SMALL                  -0x4B00  /**< Output buffer too small. */
#define MBEDTLS_ERR_ECIES_MALFORMED_DATA                    -0x4A80  /**< Encrypted data is malformed. */
#define MBEDTLS_ERR_ECIES_ALLOC_FAILED                      -0x4A00  /**< Memory allocation failed */

#if defined(MBEDTLS_ECIES_C)

#if !defined(MBEDTLS_ECIES_CIPHER_TYPE)
/*
 * Symmetric cipher that is used for internal data encryption
 *
 * Default value: MBEDTLS_CIPHER_AES_256_CBC
 */
#define MBEDTLS_ECIES_CIPHER_TYPE MBEDTLS_CIPHER_AES_256_CBC
#endif /* !MBEDTLS_ECIES_CIPHER_TYPE */

#if !defined(MBEDTLS_ECIES_CIPHER_PADDING)
/*
 * Padding for symmetric cipher that is used for padding data before encryption
 *
 * Default value: MBEDTLS_PADDING_PKCS7
 */
#define MBEDTLS_ECIES_CIPHER_PADDING MBEDTLS_PADDING_PKCS7
#endif /* !MBEDTLS_ECIES_CIPHER_PADDING */

#if !defined(MBEDTLS_ECIES_MD_TYPE)
/*
 * Digest algorithm that is used for the key derivation
 *
 * Default value: MBEDTLS_MD_SHA384
 */
#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_ECIES_MD_TYPE MBEDTLS_MD_SHA384
#elif defined(MBEDTLS_SHA256_C)
#define MBEDTLS_ECIES_MD_TYPE MBEDTLS_MD_SHA256
#elif defined(MBEDTLS_SHA1_C)
#define MBEDTLS_ECIES_MD_TYPE MBEDTLS_MD_SHA1
#else
#error "Can not define appropriate value for MBEDTLS_ECIES_MD_TYPE contant"
#endif
#endif /* !MBEDTLS_ECIES_MD_TYPE */

#if !defined(MBEDTLS_ECIES_HMAC_TYPE)
/*
 * Digest algorithm that is used to get verification tag
 *
 * Default value: MBEDTLS_MD_SHA384
 */
#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_ECIES_HMAC_TYPE MBEDTLS_MD_SHA384
#elif defined(MBEDTLS_SHA256_C)
#define MBEDTLS_ECIES_HMAC_TYPE MBEDTLS_MD_SHA256
#elif defined(MBEDTLS_SHA1_C)
#define MBEDTLS_ECIES_HMAC_TYPE MBEDTLS_MD_SHA1
#else
#error "Can not define appropriate value for MBEDTLS_ECIES_HMAC_TYPE contant"
#endif
#endif /* !MBEDTLS_ECIES_HMAC_TYPE */

#if !defined(MBEDTLS_ECIES_KDF_TYPE)
/*
 * Key derivation algorithm that is used to derive key for the symmetric cipher
 *
 * Default value: MBEDTLS_KDF_KDF2
 */
#if defined(MBEDTLS_KDF2_C)
#define MBEDTLS_ECIES_KDF_TYPE MBEDTLS_KDF_KDF2
#elif defined(MBEDTLS_KDF1_C)
#define MBEDTLS_ECIES_KDF_TYPE MBEDTLS_KDF_KDF1
#else
#error "Can not define appropriate value for MBEDTLS_ECIES_KDF_TYPE contant"
#endif
#endif /* !MBEDTLS_ECIES_KDF_TYPE */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Perform ECIES encryption.
 * \return         0 if successful
 */
int mbedtls_ecies_encrypt(mbedtls_ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
/**
 * \brief          Perform ECIES decryption.
 * \return         0 if successful
 */
int mbedtls_ecies_decrypt(mbedtls_ecp_keypair *key, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);


#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_ECIES_C */

#endif /* MBEDTLS_ECIES_H */
