/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECIES_C)

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_FAST_EC_C)
#include "mbedtls/fast_ec.h"
#endif

#if defined(MBEDTLS_ECDH_C)
#include "mbedtls/ecdh.h"
#endif

#if defined(MBEDTLS_MD_C)
#include "mbedtls/md.h"
#endif

#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#endif

#if defined(MBEDTLS_KDF_C)
#include "mbedtls/kdf.h"
#endif

#if defined(MBEDTLS_CIPHER_C)
#include "mbedtls/cipher.h"
#endif

#if defined(MBEDTLS_ASN1_PARSE_C)
#include "mbedtls/asn1.h"
#endif

#if defined(MBEDTLS_ASN1_WRITE_C)
#include "mbedtls/asn1write.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include "mbedtls/ecies_internal.h"
#include "mbedtls/ecies_envelope.h"

#define ECIES_OCTET_SIZE 8
#define ECIES_SIZE_TO_OCTETS(size) ((size + 7) / ECIES_OCTET_SIZE)

#define INVOKE_AND_CHECK(result,invocation) \
    if ((result = invocation) < 0) goto cleanup;

#define ACCUMULATE_AND_CHECK(result, len, invocation) \
do { \
    if ((result = invocation) < 0) { \
        goto cleanup; \
    } else { \
        len += result; \
        result = 0; \
    } \
} while (0)

static int asn1_get_tag_len(unsigned char *p, const unsigned char *end,
        size_t *len)
{
    int result = 0;
    unsigned char *len_p = p + 1;
    INVOKE_AND_CHECK(result,
        mbedtls_asn1_get_len(&len_p, end, len)
    );
    *len += len_p - p;
cleanup:
    return result;
}

const mbedtls_ecies_info_t* mbedtls_ecies_info_from_type(mbedtls_ecies_type_t type)
{
    switch( type )
    {
#if defined(MBEDTLS_ECP_C) && defined (MBEDTLS_ECDH_C)
        case MBEDTLS_ECIES_ECP:
            return( &mbedtls_ecies_ecp_info );
#endif
#if defined(MBEDTLS_FAST_EC_C)
        case MBEDTLS_ECIES_FAST_EC:
            return( &mbedtls_ecies_fast_ec_info );
#endif
        default:
            return( NULL );
    }
}


#if defined(MBEDTLS_ECP_C) && defined (MBEDTLS_ECDH_C)

static void * ecp_key_alloc_wrap( void )
{
    mbedtls_ecp_keypair* key = mbedtls_calloc( 1, sizeof( mbedtls_ecp_keypair ) );

    if( key != NULL ) {
        mbedtls_ecp_keypair_init( key );
    }

    return key;
}

static void ecp_key_free_wrap( void *key )
{
    mbedtls_ecp_keypair_free( (mbedtls_ecp_keypair *) key );
}

static int ecp_key_gen_ephemeral_wrap( void *src_key, void *dst_key,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_ecp_keypair* src = (mbedtls_ecp_keypair *) src_key;
    mbedtls_ecp_keypair* dst = (mbedtls_ecp_keypair *) dst_key;

    return( mbedtls_ecp_gen_key( src->grp.id, dst, f_rng, p_rng ) );
}

static int ecp_key_compute_shared_wrap( void *pub, void* prv,
        unsigned char* shared, size_t shared_len,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int result = 0;
    mbedtls_mpi shared_mpi;

    mbedtls_ecp_keypair* public = (mbedtls_ecp_keypair *) pub;
    mbedtls_ecp_keypair* private = (mbedtls_ecp_keypair *) prv;

    if (public->grp.id != private->grp.id)
        return MBEDTLS_ERR_ECIES_BAD_INPUT_DATA;

    mbedtls_mpi_init( &shared_mpi );

    INVOKE_AND_CHECK(result,
        mbedtls_ecdh_compute_shared( &public->grp, &shared_mpi, &public->Q, &private->d,
                                         f_rng, p_rng )
    );

    INVOKE_AND_CHECK(result,
        mbedtls_mpi_write_binary(&shared_mpi, shared, shared_len)
    );

cleanup:
    mbedtls_mpi_free( &shared_mpi );

    return( result );
}

static size_t ecp_key_get_shared_len_wrap( void* key )
{
    mbedtls_ecp_keypair* ecp_key = (mbedtls_ecp_keypair *) key;
    return( ECIES_SIZE_TO_OCTETS( ecp_key->grp.pbits ) );
}

static int ecp_key_write_pub_asn1_wrap( unsigned char** p, unsigned char* start, void *key )
{
    int result = 0;
    size_t len = 0;

    mbedtls_pk_context pk;

    pk.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    pk.pk_ctx = key;
    ACCUMULATE_AND_CHECK(result, len,
        mbedtls_pk_write_pubkey_der(&pk, start , *p - start)
    );
    *p -= len;
cleanup:
    if (result < 0)
        return result;
    else
        return (int)len;
}

static int ecp_key_read_pub_asn1_wrap( unsigned char** p, const unsigned char* end, void *key )
{
    int result = 0;
    mbedtls_pk_context pk;
    size_t key_len = 0;

    mbedtls_ecp_keypair* ecp_key = (mbedtls_ecp_keypair *) key;

    mbedtls_pk_init(&pk);

    INVOKE_AND_CHECK(result,
        asn1_get_tag_len(*p, end, &key_len)
    );

    INVOKE_AND_CHECK(result,
        mbedtls_pk_parse_public_key(&pk, *p, key_len)
    );
    *p += key_len;

    if (mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECKEY) ||
        mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECKEY_DH) ||
        mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA))
    {
        INVOKE_AND_CHECK(result,
            mbedtls_ecp_group_copy( &ecp_key->grp, &mbedtls_pk_ec(pk)->grp )
        );
        INVOKE_AND_CHECK(result,
            mbedtls_mpi_copy( &ecp_key->d, &mbedtls_pk_ec(pk)->d )
        );
        INVOKE_AND_CHECK(result,
            mbedtls_ecp_copy( &ecp_key->Q, &mbedtls_pk_ec(pk)->Q )
        );
    } else {
        result = MBEDTLS_ERR_ECIES_MALFORMED_DATA;
    }
cleanup:
    mbedtls_pk_free(&pk);
    return result;
}

const mbedtls_ecies_info_t mbedtls_ecies_ecp_info = {
    MBEDTLS_ECIES_ECP, // type
    "ECIES_ECP", // name
    ecp_key_alloc_wrap, // key_alloc_func
    ecp_key_free_wrap, // key_free_func
    ecp_key_gen_ephemeral_wrap, // key_gen_ephemeral_func
    ecp_key_compute_shared_wrap, // key_make_shared_func
    ecp_key_get_shared_len_wrap, // key_get_shared_len_func
    ecp_key_write_pub_asn1_wrap, // key_write_pub_asn1_func
    ecp_key_read_pub_asn1_wrap, // key_read_pub_asn1_func
};

#endif /* MBEDTLS_ECP_C &&  MBEDTLS_ECDH_C */

#if defined(MBEDTLS_FAST_EC_C)

static void * fast_ec_key_alloc_wrap( void )
{
    mbedtls_fast_ec_keypair_t* key = mbedtls_calloc( 1, sizeof( mbedtls_fast_ec_keypair_t ) );

    if( key != NULL ) {
        mbedtls_fast_ec_init( key );
    }

    return key;
}

static void fast_ec_key_free_wrap( void *key )
{
    mbedtls_fast_ec_free( (mbedtls_fast_ec_keypair_t *) key );
}

static int fast_ec_key_gen_ephemeral_wrap( void *src_key, void *dst_key,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int result = 0;

    mbedtls_fast_ec_keypair_t* src = (mbedtls_fast_ec_keypair_t *) src_key;
    mbedtls_fast_ec_keypair_t* dst = (mbedtls_fast_ec_keypair_t *) dst_key;

    INVOKE_AND_CHECK(result,
        mbedtls_fast_ec_setup( dst, src->info )
    );

    INVOKE_AND_CHECK(result,
        mbedtls_fast_ec_gen_key( dst, f_rng, p_rng )
    );

cleanup:
    return( result );
}

static int fast_ec_key_compute_shared_wrap( void *pub, void* prv,
        unsigned char* shared, size_t shared_len,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_fast_ec_keypair_t* public = (mbedtls_fast_ec_keypair_t *) pub;
    mbedtls_fast_ec_keypair_t* private = (mbedtls_fast_ec_keypair_t *) prv;

    (void) f_rng;
    (void) p_rng;

    if( mbedtls_fast_ec_get_type( public->info ) != mbedtls_fast_ec_get_type( private->info ) )
        return MBEDTLS_ERR_ECIES_BAD_INPUT_DATA;

    return( mbedtls_fast_ec_compute_shared( public, private, shared, shared_len ) );
}

static size_t fast_ec_key_get_shared_len_wrap( void* key )
{
    return( mbedtls_fast_ec_get_shared_len( ( (mbedtls_fast_ec_keypair_t *) key )->info ) );
}

static int fast_ec_key_write_pub_asn1_wrap( unsigned char** p, unsigned char* start, void *key )
{
    int result = 0;
    size_t len = 0;

    mbedtls_pk_context pk;

    pk.pk_info = mbedtls_pk_info_from_type( mbedtls_pk_from_fast_ec_type(
            mbedtls_fast_ec_get_type( ( (mbedtls_fast_ec_keypair_t *) key )->info ) ) );

    if( pk.pk_info == NULL)
        INVOKE_AND_CHECK( result, MBEDTLS_ERR_ECIES_MALFORMED_DATA );

    pk.pk_ctx = key;
    ACCUMULATE_AND_CHECK(result, len,
        mbedtls_pk_write_pubkey_der(&pk, start , *p - start)
    );
    *p -= len;
cleanup:
    if (result < 0)
        return result;
    else
        return (int)len;
}

static int fast_ec_key_read_pub_asn1_wrap( unsigned char** p, const unsigned char* end, void *key )
{
    int result = 0;
    mbedtls_pk_context pk;
    size_t key_len = 0;

    mbedtls_fast_ec_keypair_t* fast_ec_key = (mbedtls_fast_ec_keypair_t *) key;

    mbedtls_pk_init(&pk);

    INVOKE_AND_CHECK(result,
        asn1_get_tag_len(*p, end, &key_len)
    );

    INVOKE_AND_CHECK(result,
        mbedtls_pk_parse_public_key(&pk, *p, key_len)
    );
    *p += key_len;

    if (mbedtls_pk_can_do(&pk, MBEDTLS_PK_X25519) || mbedtls_pk_can_do(&pk, MBEDTLS_PK_ED25519) )
    {
        INVOKE_AND_CHECK(result,
            mbedtls_fast_ec_copy( fast_ec_key, mbedtls_pk_fast_ec(pk) )
        );
    } else {
        result = MBEDTLS_ERR_ECIES_MALFORMED_DATA;
    }
cleanup:
    mbedtls_pk_free(&pk);
    return result;
}

const mbedtls_ecies_info_t mbedtls_ecies_fast_ec_info = {
    MBEDTLS_ECIES_FAST_EC, // type
    "ECIES_FAST_EC", // name
    fast_ec_key_alloc_wrap, // key_alloc_func
    fast_ec_key_free_wrap, // key_free_func
    fast_ec_key_gen_ephemeral_wrap, // key_gen_ephemeral_func
    fast_ec_key_compute_shared_wrap, // key_make_shared_func
    fast_ec_key_get_shared_len_wrap, // key_get_shared_len_func
    fast_ec_key_write_pub_asn1_wrap, // key_write_pub_asn1_func
    fast_ec_key_read_pub_asn1_wrap, // key_read_pub_asn1_func
};

#endif /* MBEDTLS_FAST_EC_C */

#endif /* MBEDTLS_ECIES_C */
