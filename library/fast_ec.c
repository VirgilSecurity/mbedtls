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

#if defined(MBEDTLS_FAST_EC_C)

#include "mbedtls/fast_ec.h"
#include "mbedtls/fast_ec_internal.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include <string.h>

const mbedtls_fast_ec_info_t* mbedtls_fast_ec_info_from_type( mbedtls_fast_ec_type_t type )
{
    switch( type )
    {
        case MBEDTLS_FAST_EC_X25519:
            return( &mbedtls_fast_ec_x25519_info );
        case MBEDTLS_FAST_EC_ED25519:
            return( &mbedtls_fast_ec_ed25519_info );
        default:
            return( NULL );
    }
}

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}
void mbedtls_fast_ec_init( mbedtls_fast_ec_keypair_t *keypair )
{
    memset( keypair, 0, sizeof( mbedtls_fast_ec_keypair_t ) );
}

int mbedtls_fast_ec_setup(mbedtls_fast_ec_keypair_t *keypair, const mbedtls_fast_ec_info_t* info )
{
    if( info == NULL || keypair == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    keypair->public_key = mbedtls_calloc( 1, info->key_len );
    keypair->private_key = mbedtls_calloc( 1, info->key_len );

    if( keypair->public_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_ALLOC_FAILED );

    if( keypair->private_key == NULL )
    {
        if( keypair->public_key != NULL )
        {
            mbedtls_free( keypair->public_key );
            keypair->public_key = NULL;
        }
        return( MBEDTLS_ERR_FAST_EC_ALLOC_FAILED );
    }

    keypair->info = info;

    return( 0 );
}

void mbedtls_fast_ec_free( mbedtls_fast_ec_keypair_t *keypair )
{
    if( keypair == NULL )
        return;

    if( keypair->public_key != NULL )
    {
        mbedtls_zeroize( keypair->public_key, keypair->info->key_len );
        mbedtls_free( keypair->public_key );
    }

    if( keypair->private_key != NULL )
    {
        mbedtls_zeroize( keypair->private_key, keypair->info->key_len );
        mbedtls_free( keypair->private_key );
    }

    memset( keypair, 0, sizeof( mbedtls_fast_ec_keypair_t ) );
}

int mbedtls_fast_ec_copy(mbedtls_fast_ec_keypair_t* dst, const mbedtls_fast_ec_keypair_t* src)
{
    int ret = 0;

    if( src == NULL || src->info == NULL || dst->info != NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( ( ret = mbedtls_fast_ec_setup( dst, src->info ) ) != 0 )
        return( ret );

    memcpy( dst->public_key, src->public_key, src->info->key_len );
    memcpy( dst->private_key, src->private_key, src->info->key_len );

    return( 0 );
}

int mbedtls_fast_ec_gen_key( mbedtls_fast_ec_keypair_t *keypair,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( keypair == NULL || keypair->info == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    return keypair->info->gen_key_func( keypair->public_key, keypair->private_key, f_rng, p_rng );
}

int mbedtls_fast_ec_compute_pub( mbedtls_fast_ec_keypair_t *keypair )
{
    if( keypair == NULL || keypair->info == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    return( keypair->info->get_pub_func( keypair->public_key, keypair->private_key ) );
}

int mbedtls_fast_ec_sign( const mbedtls_fast_ec_keypair_t* keypair,
                unsigned char* sig, size_t *sig_len,
                const unsigned char* data, size_t data_len )
{
    int ret = 0;

    if( keypair == NULL || keypair->info == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( keypair->info->sign_func == NULL )
        return( MBEDTLS_ERR_FAST_EC_FEATURE_UNAVAILABLE );

    if ( ( ret = keypair->info->sign_func( sig, keypair->private_key, data, data_len ) ) != 0 )
        return( ret );

    *sig_len = keypair->info->sig_len;
    return( 0 );
}

int mbedtls_fast_ec_verify( const mbedtls_fast_ec_keypair_t* keypair,
                const unsigned char* sig, size_t sig_len,
                const unsigned char* data, size_t data_len)
{
    if( keypair == NULL || keypair->info == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( keypair->info->verify_func == NULL )
        return( MBEDTLS_ERR_FAST_EC_FEATURE_UNAVAILABLE );

    if( sig_len != keypair->info->sig_len )
        return( MBEDTLS_ERR_FAST_EC_SIG_LEN_MISMATCH );

    if ( keypair->info->verify_func( sig, keypair->public_key, data, data_len ) != 0 )
        return( MBEDTLS_ERR_FAST_EC_VERIFY_FAILED );

    return( 0 );
}

int mbedtls_fast_ec_compute_shared( const mbedtls_fast_ec_keypair_t* pub, const mbedtls_fast_ec_keypair_t* prv,
                unsigned char* shared, size_t shared_len )
{
    if( pub == NULL || pub->info == NULL || pub->public_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if(  prv == NULL || prv->info == NULL || prv->private_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( pub->info->type != prv->info->type )
        return( MBEDTLS_ERR_FAST_EC_PUB_PRV_MISMATCH );

    return( pub->info->compute_shared_func( pub->public_key, prv->private_key, shared, shared_len ) );
}

int mbedtls_fast_ec_check_pub_priv( const mbedtls_fast_ec_keypair_t *pub, const mbedtls_fast_ec_keypair_t *prv )
{
    int ret = 0;
    unsigned char *public_key = NULL;

    if( pub == NULL || pub->info == NULL || pub->public_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if(  prv == NULL || prv->info == NULL || prv->private_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( pub->info->type != prv->info->type )
        return( MBEDTLS_ERR_FAST_EC_PUB_PRV_MISMATCH );

    if( ( public_key = mbedtls_calloc( 1, prv->info->key_len ) ) == NULL )
        return( MBEDTLS_ERR_FAST_EC_ALLOC_FAILED );

    if( ( ret = prv->info->get_pub_func( public_key, prv->private_key ) ) != 0 )
        goto cleanup;

    if( memcmp( pub->public_key, public_key, pub->info->key_len ) != 0 )
    {
        ret = MBEDTLS_ERR_FAST_EC_PUB_PRV_MISMATCH;
        goto cleanup;
    }

cleanup:
    mbedtls_free( public_key );
    return( ret );
}

mbedtls_fast_ec_type_t mbedtls_fast_ec_get_type( const mbedtls_fast_ec_info_t* info )
{
    if( info == NULL )
        return( MBEDTLS_FAST_EC_NONE );

    return( info->type );
}

const char* mbedtls_fast_ec_get_name( const mbedtls_fast_ec_info_t* info )
{
    if( info == NULL )
        return( NULL);

    return( info->name );
}

size_t mbedtls_fast_ec_get_key_bitlen( const mbedtls_fast_ec_info_t* info )
{
    if( info == NULL )
        return( 0 );

    return( info->key_bitlen );
}

size_t mbedtls_fast_ec_get_key_len( const mbedtls_fast_ec_info_t* info )
{
    if( info == NULL )
        return( 0 );

    return( info->key_len );
}

size_t mbedtls_fast_ec_get_sig_len( const mbedtls_fast_ec_info_t* info )
{
    if( info == NULL )
        return( 0 );

    return( info->sig_len );
}

size_t mbedtls_fast_ec_get_shared_len( const mbedtls_fast_ec_info_t* info )
{
    if( info == NULL )
        return( 0 );

    return( info->dh_len );
}

#endif /* MBEDTLS_FAST_EC_C */
