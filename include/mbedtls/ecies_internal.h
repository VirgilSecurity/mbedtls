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

#ifndef MBEDTLS_ECIES_WRAP_H
#define MBEDTLS_ECIES_WRAP_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECIES_C)

#include "ecies.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mbedtls_ecies_info_t
{
    /** ECIES implementation identifier */
    mbedtls_ecies_type_t type;

    /** Name of the ECIES implementation details */
    const char* name;

    /** Allocate a new key */
    void * (*key_alloc_func)( void );

    /** Free the given key */
    void (*key_free_func)( void *key );

    /** Generate ephemeral key based on parameters of the source key */
    int (*key_gen_ephemeral_func)( void *src_key, void *dst_key,
            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

    /** Make shared key on a given keys */
    int (*key_compute_shared_func)( void *pub, void* prv,
            unsigned char* shared, size_t shared_len,
            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

    /** Get shared key length in bytes */
    size_t (*key_get_shared_len_func)( void* key );

    /** Write public as ASN.1 structure */
    int (*key_write_pub_asn1_func)(unsigned char** p, unsigned char* start, void *key);

    /** Read public from ASN.1 structure */
    int (*key_read_pub_asn1_func)(unsigned char** p, const unsigned char* end, void *key);
};

#if defined(MBEDTLS_ECP_C) && defined (MBEDTLS_ECDH_C)
extern const mbedtls_ecies_info_t mbedtls_ecies_ecp_info;
#endif

#if defined(MBEDTLS_FAST_EC_C)
extern const mbedtls_ecies_info_t mbedtls_ecies_fast_ec_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /** MBEDTLS_ECIES_C */

#endif /** MBEDTLS_ECIES_WRAP_H */

