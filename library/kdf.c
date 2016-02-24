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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_KDF_C)

#include "mbedtls/kdf.h"
#include "mbedtls/kdf_internal.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <string.h>

static const int supported_kdfs[] = {

#if defined(MBEDTLS_KDF1_C)
        MBEDTLS_KDF_KDF1,
#endif

#if defined(MBEDTLS_KDF2_C)
        MBEDTLS_KDF_KDF2,
#endif
        MBEDTLS_KDF_NONE
};

const int *mbedtls_kdf_list( void )
{
    return( supported_kdfs );
}

const mbedtls_kdf_info_t *mbedtls_kdf_info_from_string( const char *kdf_name )
{
    if( NULL == kdf_name )
        return( NULL );

    /* Get the appropriate key derivation function information */
#if defined(MBEDTLS_KDF1_C)
    if( !strcmp( "KDF1", kdf_name ) )
        return mbedtls_kdf_info_from_type( MBEDTLS_KDF_KDF1 );
#endif
#if defined(MBEDTLS_KDF2_C)
    if( !strcmp( "KDF2", kdf_name ) )
        return mbedtls_kdf_info_from_type( MBEDTLS_KDF_KDF2 );
#endif
    return( NULL );
}

const mbedtls_kdf_info_t *mbedtls_kdf_info_from_type( mbedtls_kdf_type_t kdf_type )
{
    switch( kdf_type )
    {
#if defined(MBEDTLS_KDF1_C)
        case MBEDTLS_KDF_KDF1:
            return( &mbedtls_kdf1_info );
#endif
#if defined(MBEDTLS_KDF2_C)
        case MBEDTLS_KDF_KDF2:
            return( &mbedtls_kdf2_info );
#endif
        default:
            return( NULL );
    }
}

const char *mbedtls_kdf_get_name( const mbedtls_kdf_info_t *kdf_info )
{
    if( kdf_info == NULL )
        return( NULL );

    return kdf_info->name;
}

mbedtls_kdf_type_t mbedtls_kdf_get_type( const mbedtls_kdf_info_t *kdf_info )
{
    if( kdf_info == NULL )
        return( MBEDTLS_KDF_NONE );

    return kdf_info->type;
}

int mbedtls_kdf( const mbedtls_kdf_info_t *kdf_info, const mbedtls_md_info_t *md_info,
        const unsigned char *input, size_t ilen, unsigned char *output, size_t olen)
{
    int res = 0;

    if( kdf_info == NULL )
        return( MBEDTLS_ERR_KDF_BAD_INPUT_DATA );

    if ( ( res = kdf_info->kdf_func( md_info, input, ilen, output, olen ) ) != 0 )
    {
        return MBEDTLS_ERR_KDF_BAD_INPUT_DATA | res;
    }
    return 0;
}

#endif /* MBEDTLS_KDF_C */
