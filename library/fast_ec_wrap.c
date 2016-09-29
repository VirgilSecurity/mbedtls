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

#include "mbedtls/fast_ec_internal.h"

#if defined(MBEDTLS_ED25519_C)
#include "mbedtls/ed25519.h"
#endif


#if defined(MBEDTLS_ED25519_C)

static int x25519_gen_key_wrap( unsigned char* public_key, unsigned char* private_key,
                int (*f_rng)(void *, unsigned char *, size_t),
                void *p_rng )
{
    int ret = 0;

    if( public_key == NULL || private_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( ( ret = f_rng( p_rng, private_key, MBEDTLS_ED25519_KEY_LEN ) ) != 0 )
        return( ret );

    mbedtls_curve25519_get_pubkey( public_key, private_key );

    return( 0 );
}

static int x25519_get_pub_wrap( unsigned char* public_key, const unsigned char* private_key )
{
    if( public_key == NULL || private_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    mbedtls_curve25519_get_pubkey( public_key, private_key );

    return( 0 );
}

static int x25519_compute_shared_func( const unsigned char* public_key, const unsigned char* private_key,
                                unsigned char* shared, size_t shared_len )
{
    if( public_key == NULL || private_key == NULL || shared == NULL || shared_len < MBEDTLS_ED25519_DH_LEN)
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( mbedtls_curve25519_key_exchange( shared, public_key, private_key ) != 0 )
        return( MBEDTLS_ERR_FAST_EC_SHARED_WEAK_KEY );

    return( 0 );
}

static int ed25519_gen_key_wrap( unsigned char* public_key, unsigned char* private_key,
                int (*f_rng)(void *, unsigned char *, size_t),
                void *p_rng )
{
    int ret = 0;

    if( public_key == NULL || private_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( ( ret = f_rng( p_rng, private_key, MBEDTLS_ED25519_KEY_LEN ) ) != 0 )
        return( ret );

    mbedtls_ed25519_get_pubkey( public_key, private_key );

    return( 0 );
}

static int ed25519_get_pub_wrap( unsigned char* public_key, const unsigned char* private_key )
{
    if( public_key == NULL || private_key == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    mbedtls_ed25519_get_pubkey( public_key, private_key );

    return( 0 );
}

static int ed25519_sign_wrap( unsigned char* sig, const unsigned char* private_key,
                const unsigned char* data, size_t data_len )
{
    if( sig == NULL || private_key == NULL || data == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    mbedtls_ed25519_sign( sig, private_key, data, data_len );
    return( 0 );
}

static int ed25519_verify_wrap( const unsigned char* sig, const unsigned char* public_key,
                const unsigned char* data, size_t data_len )
{
    if( sig == NULL || public_key == NULL || data == NULL )
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    if( mbedtls_ed25519_verify( sig, public_key, data, data_len ) != 0)
        return( MBEDTLS_ERR_FAST_EC_VERIFY_FAILED );

    return( 0 );
}

static int ed25519_compute_shared_func( const unsigned char* public_key, const unsigned char* private_key,
                                unsigned char* shared, size_t shared_len )
{
    unsigned char x25519_public_key[MBEDTLS_ED25519_KEY_LEN];
    unsigned char x25519_private_key[MBEDTLS_ED25519_KEY_LEN];

    if( public_key == NULL || private_key == NULL || shared == NULL || shared_len < MBEDTLS_ED25519_DH_LEN)
        return( MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA );

    mbedtls_ed25519_pubkey_to_curve25519(x25519_public_key, public_key);
    mbedtls_ed25519_key_to_curve25519(x25519_private_key, private_key);

    if( mbedtls_curve25519_key_exchange( shared, x25519_public_key, x25519_private_key ) != 0 )
        return( MBEDTLS_ERR_FAST_EC_SHARED_WEAK_KEY );

    return( 0 );
}

const mbedtls_fast_ec_info_t mbedtls_fast_ec_x25519_info = {
    MBEDTLS_FAST_EC_X25519,      // type
    "X25519",                    // name
    32,                          // key_len
    254,                         // key_bitlen
    64,                          // sig_len
    32,                          // shared_len
    x25519_gen_key_wrap,         // key_gen_func
    x25519_get_pub_wrap,         // get_pub_func
    NULL,                        // sign_func
    NULL,                        // verify_func
    x25519_compute_shared_func,   // compute_shared_func
};

const mbedtls_fast_ec_info_t mbedtls_fast_ec_ed25519_info = {
    MBEDTLS_FAST_EC_ED25519,      // type
    "ED25519",                    // name
    32,                           // key_len
    254,                          // key_bitlen
    64,                           // sig_len
    32,                           // shared_len
    ed25519_gen_key_wrap,         // key_gen_func
    ed25519_get_pub_wrap,         // get_pub_func
    ed25519_sign_wrap,            // sign_func
    ed25519_verify_wrap,          // verify_func
    ed25519_compute_shared_func,  // compute_shared_func
};

#endif

#endif /* MBEDTLS_FAST_EC_C */
