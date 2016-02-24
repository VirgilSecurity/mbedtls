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

#ifndef MBEDTLS_KDF_H
#define MBEDTLS_KDF_H

#include <string.h>

#include "md.h"

#define MBEDTLS_ERR_KDF_BAD_INPUT_DATA                     -0x5F80  /**< Bad input parameters to function. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MBEDTLS_KDF_NONE=0,
    MBEDTLS_KDF_KDF1,
    MBEDTLS_KDF_KDF2,
} mbedtls_kdf_type_t;

/**
 * Opaque struct defined in kdf_internal.h
 */
typedef struct mbedtls_kdf_info_t mbedtls_kdf_info_t;

/**
 * \brief Returns the list of key derivation functions supported by the key derivation module.
 *
 * \return          a statically allocated array of key derivation functions, the last entry
 *                  is 0.
 */
const int *mbedtls_kdf_list( void );

/**
 * \brief           Returns the key derivation function information associated with the
 *                  given key derivation function name.
 *
 * \param kdf_name  Name of the key derivation function to search for.
 *
 * \return          The key derivation function information associated with kdf_name or
 *                  NULL if not found.
 */
const mbedtls_kdf_info_t *mbedtls_kdf_info_from_string( const char *kdf_name );

/**
 * \brief           Returns the key derivation function information associated with the
 *                  given key derivation function type.
 *
 * \param kdf_type  type of key derivation function to search for.
 *
 * \return          The key derivation function information associated with kdf_type or
 *                  NULL if not found.
 */
const mbedtls_kdf_info_t *mbedtls_kdf_info_from_type( mbedtls_kdf_type_t kdf_type );

/**
 * \brief           Returns the name of the key derivation function.
 *
 * \param kdf_info  key derivation function info
 *
 * \return          name of the key derivation function.
 */
const char *mbedtls_kdf_get_name( const mbedtls_kdf_info_t *kdf_info );

/**
 * \brief           Returns the type of the key derivation function.
 *
 * \param kdf_info  key derivation function info
 *
 * \return          type of the key derivation function.
 */
mbedtls_kdf_type_t mbedtls_kdf_get_type( const mbedtls_kdf_info_t *kdf_info );

/**
 * \brief          Output = message_key derivation function( input buffer )
 *
 * \param kdf_info key derivation function info
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   Generic key derivation function checksum result
 *
 * \returns        0 on success, MBEDTLS_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
int mbedtls_kdf( const mbedtls_kdf_info_t *kdf_info, const mbedtls_md_info_t *md_info,
        const unsigned char *input, size_t ilen, unsigned char *output, size_t olen );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_KDF_H */
