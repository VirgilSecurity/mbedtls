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
#ifndef MBEDTLS_FAST_EC_WRAP_H
#define MBEDTLS_FAST_EC_WRAP_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "fast_ec.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fast EC information.
 * Allows Fast EC functions to be called in a generic way.
 */
 struct mbedtls_fast_ec_info_t {
    /** Fast EC identifier */
    mbedtls_fast_ec_type_t type;

    /** Fast EC name */
    const char *name;

    /** Key length */
    size_t key_len;

    /** Key length in bits */
    size_t key_bitlen;

    /** Signature length */
    size_t sig_len;

    /** Shared key length */
    size_t dh_len;

    /** Generate keypair */
    int (* gen_key_func)( unsigned char* public_key, unsigned char* private_key,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng );

    /** Get public key from private */
    int (* get_pub_func)( unsigned char* public_key, const unsigned char* private_key );

    /** Sign data */
    int (* sign_func)( unsigned char* sig, const unsigned char* private_key,
                       const unsigned char* data, size_t data_len );

    /** Verify Data */
    int (* verify_func)( const unsigned char* sig, const unsigned char* public_key,
                         const unsigned char* data, size_t data_len );

    /** Compute shared */
    int (*compute_shared_func)( const unsigned char* public_key, const unsigned char* private_key,
                                unsigned char* shared, size_t shared_len );


};

#if defined(MBEDTLS_ED25519_C)
extern const mbedtls_fast_ec_info_t mbedtls_fast_ec_x25519_info;
extern const mbedtls_fast_ec_info_t mbedtls_fast_ec_ed25519_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_FAST_EC_WRAP_H */
