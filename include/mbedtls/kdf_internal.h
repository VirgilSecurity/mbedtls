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

#ifndef MBEDTLS_KDF_INTERNAL_H
#define MBEDTLS_KDF_INTERNAL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#include "kdf.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Key derivation function information.
 * Allows Key derivation functions to be called in a generic way.
 */
struct mbedtls_kdf_info_t
{
    /** Key derivation function identifier */
    mbedtls_kdf_type_t type;

    /** Name of the Key derivation function */
    const char * name;

    /** Key derivation function */
    int (*kdf_func)(const mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
            unsigned char *output, size_t olen);
};

#if defined(MBEDTLS_KDF1_C)
extern const mbedtls_kdf_info_t mbedtls_kdf1_info;
#endif
#if defined(MBEDTLS_KDF2_C)
extern const mbedtls_kdf_info_t mbedtls_kdf2_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_KDF_INTERNAL_H */
