/*
 *  Public Key layer for writing key files and structures
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PK_WRITE_C)

#include "mbedtls/pk.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#include <string.h>

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif
#if defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif
#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif
#if defined(MBEDTLS_PKCS12_C)
#include "mbedtls/pkcs12.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#if defined(MBEDTLS_RSA_C)
/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_write_rsa_pubkey( unsigned char **p, unsigned char *start,
                                  mbedtls_rsa_context *rsa )
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( p, start, &rsa->E ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( p, start, &rsa->N ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/*
 * EC public key is an EC point
 */
static int pk_write_ec_pubkey( unsigned char **p, unsigned char *start,
                                 mbedtls_ecp_keypair *ec )
{
    int ret;
    size_t len = 0;
    unsigned char buf[MBEDTLS_ECP_MAX_PT_LEN];

    if( ( ret = mbedtls_ecp_point_write_binary( &ec->grp, &ec->Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &len, buf, sizeof( buf ) ) ) != 0 )
    {
        return( ret );
    }

    if( *p < start || (size_t)( *p - start ) < len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *p -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}

/*
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 * }
 */
static int pk_write_ec_param( unsigned char **p, unsigned char *start,
                                mbedtls_ecp_keypair *ec )
{
    int ret;
    size_t len = 0;
    const char *oid;
    size_t oid_len;

    if( ( ret = mbedtls_oid_get_oid_by_ec_grp( ec->grp.id, &oid, &oid_len ) ) != 0 )
        return( ret );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid, oid_len ) );

    return( (int) len );
}
#endif /* MBEDTLS_ECP_C */

int mbedtls_pk_write_pubkey( unsigned char **p, unsigned char *start,
                     const mbedtls_pk_context *key )
{
    int ret;
    size_t len = 0;

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_RSA )
        MBEDTLS_ASN1_CHK_ADD( len, pk_write_rsa_pubkey( p, start, mbedtls_pk_rsa( *key ) ) );
    else
#endif
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
        MBEDTLS_ASN1_CHK_ADD( len, pk_write_ec_pubkey( p, start, mbedtls_pk_ec( *key ) ) );
    else
#endif
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    return( (int) len );
}

int mbedtls_pk_write_pubkey_der( mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    const char *oid;

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_pk_write_pubkey( &c, buf, key ) );

    if( c - buf < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_BIT_STRING ) );

    if( ( ret = mbedtls_oid_get_oid_by_pk_alg( mbedtls_pk_get_type( key ),
                                       &oid, &oid_len ) ) != 0 )
    {
        return( ret );
    }

#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
    {
        MBEDTLS_ASN1_CHK_ADD( par_len, pk_write_ec_param( &c, buf, mbedtls_pk_ec( *key ) ) );
    }
#endif

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, buf, oid, oid_len,
                                                        par_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

int mbedtls_pk_write_key_der( mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c = buf + size;
    size_t len = 0;

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_RSA )
    {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa( *key );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->QP ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->DQ ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->DP ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->Q ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->P ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->D ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->E ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->N ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, 0 ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    }
    else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
    {
        mbedtls_ecp_keypair *ec = mbedtls_pk_ec( *key );
        size_t pub_len = 0, par_len = 0;

        /*
         * RFC 5915, or SEC1 Appendix C.4
         *
         * ECPrivateKey ::= SEQUENCE {
         *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
         *      privateKey     OCTET STRING,
         *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
         *      publicKey  [1] BIT STRING OPTIONAL
         *    }
         */

        /* publicKey */
        MBEDTLS_ASN1_CHK_ADD( pub_len, pk_write_ec_pubkey( &c, buf, ec ) );

        if( c - buf < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
        *--c = 0;
        pub_len += 1;

        MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_len( &c, buf, pub_len ) );
        MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_BIT_STRING ) );

        MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_len( &c, buf, pub_len ) );
        MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_tag( &c, buf,
                            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
        len += pub_len;

        /* parameters */
        MBEDTLS_ASN1_CHK_ADD( par_len, pk_write_ec_param( &c, buf, ec ) );

        MBEDTLS_ASN1_CHK_ADD( par_len, mbedtls_asn1_write_len( &c, buf, par_len ) );
        MBEDTLS_ASN1_CHK_ADD( par_len, mbedtls_asn1_write_tag( &c, buf,
                            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) );
        len += par_len;

        /* privateKey: write as MPI then fix tag */
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &ec->d ) );
        *c = MBEDTLS_ASN1_OCTET_STRING;

        /* version */
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, 1 ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    }
    else
#endif /* MBEDTLS_ECP_C */
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    return( (int) len );
}

#if defined(MBEDTLS_PK_WRITE_PKCS8_C)
int mbedtls_pk_write_key_pkcs8_der( mbedtls_pk_context *key, unsigned char *buf, size_t size,
                                  const unsigned char *pwd, size_t pwdlen,
                                  const unsigned char *pbe, size_t pbelen )
{
    int ret;
    unsigned char *c = buf + size;
    size_t len = 0, par_len = 0, oid_len = 0;
    const char *oid;

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_RSA )
    {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa( *key );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->QP ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->DQ ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->DP ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->Q ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->P ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->D ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->E ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->N ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, 0 ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    }
    else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
    {
        mbedtls_ecp_keypair *ec = mbedtls_pk_ec( *key );
        size_t pub_len = 0;

        /*
         * RFC 5915, or SEC1 Appendix C.4
         *
         * ECPrivateKey ::= SEQUENCE {
         *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
         *      privateKey     OCTET STRING,
         *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
         *      publicKey  [1] BIT STRING OPTIONAL
         *    }
         */

        /* publicKey */
        MBEDTLS_ASN1_CHK_ADD( pub_len, pk_write_ec_pubkey( &c, buf, ec ) );

        if( c - buf < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
        *--c = 0;
        pub_len += 1;

        MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_len( &c, buf, pub_len ) );
        MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_BIT_STRING ) );

        MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_len( &c, buf, pub_len ) );
        MBEDTLS_ASN1_CHK_ADD( pub_len, mbedtls_asn1_write_tag( &c, buf,
                            MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) );
        len += pub_len;

        /* privateKey: write as MPI then fix tag */
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &ec->d ) );
        *c = MBEDTLS_ASN1_OCTET_STRING;

        /* version */
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, 1 ) );

        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );
    }
    else
#endif /* MBEDTLS_ECP_C */
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    /*
     * Write private key to the PrivatKeyInfo object (PKCS#8 v1.2)
     *
     *    PrivateKeyInfo ::= SEQUENCE {
     *      version                   Version,
     *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
     *      privateKey                PrivateKey,
     *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
     *
     *    Version ::= INTEGER
     *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *    PrivateKey ::= OCTET STRING
     */

    /* privateKey: mark as octet string */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_OCTET_STRING ) );

    /* privateKeyAlgorithm */
    if( ( ret = mbedtls_oid_get_oid_by_pk_alg( mbedtls_pk_get_type( key ),
                                               &oid, &oid_len ) ) != 0 )
    {
        return( ret );
    }

#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
    {
        MBEDTLS_ASN1_CHK_ADD( par_len, pk_write_ec_param( &c, buf, mbedtls_pk_ec( *key ) ) );
    }
#endif

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, buf, oid, oid_len, par_len ) );

    /* version */
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, 0 ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    /*
     * Encrypt private key and write it to the
     *     EncryptedPrivatKeyInfo object (PKCS#8)
     *
     *  EncryptedPrivateKeyInfo ::= SEQUENCE {
     *    encryptionAlgorithm  EncryptionAlgorithmIdentifier,
     *    encryptedData        EncryptedData
     *  }
     *
     *  EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
     *
     *  EncryptedData ::= OCTET STRING
     *
     *  The EncryptedData OCTET STRING is a PKCS#8 PrivateKeyInfo
     */
    if( pwd != NULL && pwdlen > 0 && len > 0)
    {
        mbedtls_cipher_type_t cipher_alg;
        mbedtls_md_type_t md_alg;
        mbedtls_asn1_buf pbe_alg_oid, pbe_params;
        unsigned char *pbe_buf = NULL;
        size_t pbe_out_len = 0;
        unsigned char *pbe_c = (unsigned char *)pbe;

    #if !defined(MBEDTLS_PKCS12_C) && !defined(MBEDTLS_PKCS5_C)
        ((void) pwd);
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
    #endif


        if( ( ret = mbedtls_asn1_get_alg( &pbe_c, pbe_c + pbelen, &pbe_alg_oid, &pbe_params ) ) != 0 )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA + ret );

        /*
         * Encrypt Data with appropriate PBE
         */
        pbe_buf = mbedtls_calloc(1, len + MBEDTLS_MAX_BLOCK_LENGTH);
        if (pbe_buf == NULL)
        {
            return MBEDTLS_ERR_PK_ALLOC_FAILED;
        }

    #if defined(MBEDTLS_PKCS12_C)
        if( mbedtls_oid_get_pkcs12_pbe_alg( &pbe_alg_oid, &md_alg, &cipher_alg ) == 0 )
        {
            if( ( ret = mbedtls_pkcs12_pbe_ext( &pbe_params, MBEDTLS_PKCS12_PBE_ENCRYPT,
                                                cipher_alg, md_alg,
                                                pwd, pwdlen, c, len, pbe_buf, &pbe_out_len ) ) != 0 )
            {
                mbedtls_free( pbe_buf );
                return( ret );
            }
        }
        else if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS12_PBE_SHA1_RC4_128, &pbe_alg_oid ) == 0 )
        {
            if( ( ret = mbedtls_pkcs12_pbe_sha1_rc4_128( &pbe_params,
                                                         MBEDTLS_PKCS12_PBE_ENCRYPT,
                                                         pwd, pwdlen,
                                                         c, len, pbe_buf ) ) != 0 )
            {
                mbedtls_free( pbe_buf );
                return( ret );
            }
            // RC4: len(output) == len(input)
            pbe_out_len = len;
        }
        else
    #endif /* MBEDTLS_PKCS12_C */
    #if defined(MBEDTLS_PKCS5_C)
        if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS5_PBES2, &pbe_alg_oid ) == 0 )
        {
            if( ( ret = mbedtls_pkcs5_pbes2_ext( &pbe_params, MBEDTLS_PKCS5_ENCRYPT, pwd, pwdlen,
                                                 c, len, pbe_buf, &pbe_out_len ) ) != 0 )
            {
                mbedtls_free( pbe_buf );
                return( ret );
            }
        }
    #endif /* MBEDTLS_PKCS5_C */

        /* copy encrypted data to the target buffer */
        c = buf + size - pbe_out_len;
        memcpy( c, pbe_buf, pbe_out_len );
        len = pbe_out_len;
        mbedtls_free( pbe_buf );
        pbe_buf = NULL;

        /* encryptedData: mark as octet string */
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_OCTET_STRING ) );

        /* pbe algorithms */
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( &c, buf, pbe, pbelen ) );

        /* top header */
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE ) );
    }

    return( (int) len );
}
#endif /* MBEDTLS_PK_WRITE_PKCS8_C */

#if defined(MBEDTLS_PEM_WRITE_C)

#define PEM_BEGIN_PUBLIC_KEY    "-----BEGIN PUBLIC KEY-----\n"
#define PEM_END_PUBLIC_KEY      "-----END PUBLIC KEY-----\n"

#define PEM_BEGIN_PRIVATE_KEY_RSA   "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_RSA     "-----END RSA PRIVATE KEY-----\n"
#define PEM_BEGIN_PRIVATE_KEY_EC    "-----BEGIN EC PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_EC      "-----END EC PRIVATE KEY-----\n"
#define PEM_BEGIN_PRIVATE_KEY       "-----BEGIN PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY         "-----END PRIVATE KEY-----\n"
#define PEM_BEGIN_ENC_PRIVATE_KEY   "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
#define PEM_END_ENC_PRIVATE_KEY     "-----END ENCRYPTED PRIVATE KEY-----\n"

/*
 * Max sizes of key per types. Shown as tag + len (+ content).
 */

#if defined(MBEDTLS_RSA_C)
/*
 * RSA public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {          1 + 3
 *       algorithm            AlgorithmIdentifier,  1 + 1 (sequence)
 *                                                + 1 + 1 + 9 (rsa oid)
 *                                                + 1 + 1 (params null)
 *       subjectPublicKey     BIT STRING }          1 + 3 + (1 + below)
 *  RSAPublicKey ::= SEQUENCE {                     1 + 3
 *      modulus           INTEGER,  -- n            1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER   -- e            1 + 3 + MPI_MAX + 1
 *  }
 */
#define RSA_PUB_DER_MAX_BYTES   38 + 2 * MBEDTLS_MPI_MAX_SIZE

/*
 * RSA private keys:
 *  RSAPrivateKey ::= SEQUENCE {                    1 + 3
 *      version           Version,                  1 + 1 + 1
 *      modulus           INTEGER,                  1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER,                  1 + 3 + MPI_MAX + 1
 *      privateExponent   INTEGER,                  1 + 3 + MPI_MAX + 1
 *      prime1            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      prime2            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      exponent1         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      exponent2         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      coefficient       INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      otherPrimeInfos   OtherPrimeInfos OPTIONAL  0 (not supported)
 *  }
 */
#define MPI_MAX_SIZE_2          MBEDTLS_MPI_MAX_SIZE / 2 + \
                                MBEDTLS_MPI_MAX_SIZE % 2
#define RSA_PRV_DER_MAX_BYTES   47 + 3 * MBEDTLS_MPI_MAX_SIZE \
                                   + 5 * MPI_MAX_SIZE_2

#else /* MBEDTLS_RSA_C */

#define RSA_PUB_DER_MAX_BYTES   0
#define RSA_PRV_DER_MAX_BYTES   0

#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/*
 * EC public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {      1 + 2
 *    algorithm         AlgorithmIdentifier,    1 + 1 (sequence)
 *                                            + 1 + 1 + 7 (ec oid)
 *                                            + 1 + 1 + 9 (namedCurve oid)
 *    subjectPublicKey  BIT STRING              1 + 2 + 1               [1]
 *                                            + 1 (point format)        [1]
 *                                            + 2 * ECP_MAX (coords)    [1]
 *  }
 */
#define ECP_PUB_DER_MAX_BYTES   30 + 2 * MBEDTLS_ECP_MAX_BYTES

/*
 * EC private keys:
 * ECPrivateKey ::= SEQUENCE {                  1 + 2
 *      version        INTEGER ,                1 + 1 + 1
 *      privateKey     OCTET STRING,            1 + 1 + ECP_MAX
 *      parameters [0] ECParameters OPTIONAL,   1 + 1 + (1 + 1 + 9)
 *      publicKey  [1] BIT STRING OPTIONAL      1 + 2 + [1] above
 *    }
 */
#define ECP_PRV_DER_MAX_BYTES   29 + 3 * MBEDTLS_ECP_MAX_BYTES

#else /* MBEDTLS_ECP_C */

#define ECP_PUB_DER_MAX_BYTES   0
#define ECP_PRV_DER_MAX_BYTES   0

#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_PK_WRITE_PKCS8_C)

/*
 * PKCS#8 v1.2 with RSA private key:
 * PrivateKeyInfo ::= SEQUENCE {                           1 + 2
 *   version             Version,                          1 + 1 + 1
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,    1 + 1 (sequence)
 *                                                       + 1 + 1 + 9 (rsa oid)
 *                                                       + 1 + 1 (params null)
 *   privateKey          PrivateKey,                       0 (appended below)
 *   attributes          [0]  IMPLICIT Attributes OPTIONAL 0 (not supported)
 * }
 */
#define PKCS8_RSA_PRV_DER_MAX_BYTES 21

/*
 * PKCS#8 v1.2 with EC private key:
 * PrivateKeyInfo ::= SEQUENCE {                           1 + 2
 *   version             Version,                          1 + 1 + 1
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,    1 + 1 (sequence)
 *                                                       + 1 + 1 + 7 (ec oid)
 *                                                       + 1 + 1 + 9 (namedCurve oid)
 *   privateKey          PrivateKey,                       0 (appended below)
 *   attributes          [0]  IMPLICIT Attributes OPTIONAL 0 (not supported)
 * }
 */
#define PKCS8_EC_PRV_DER_MAX_BYTES 28

#define PKCS8_PRV_DER_MAX_BYTES \
        PKCS8_RSA_PRV_DER_MAX_BYTES > PKCS8_EC_PRV_DER_MAX_BYTES ? \
        PKCS8_RSA_PRV_DER_MAX_BYTES : PKCS8_EC_PRV_DER_MAX_BYTES
#else /* MBEDTLS_PK_WRITE_PKCS8_C */
#define PKCS8_PRV_DER_MAX_BYTES 0
#endif /* MBEDTLS_PK_WRITE_PKCS8_C */

#define PUB_DER_MAX_BYTES   RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                            RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES
#define PRV_DER_MAX_BYTES   RSA_PRV_DER_MAX_BYTES > ECP_PRV_DER_MAX_BYTES ? \
                            (RSA_PRV_DER_MAX_BYTES + (PKCS8_PRV_DER_MAX_BYTES)) : \
                            (ECP_PRV_DER_MAX_BYTES + (PKCS8_PRV_DER_MAX_BYTES))

int mbedtls_pk_write_pubkey_pem( mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char output_buf[PUB_DER_MAX_BYTES];
    size_t olen = 0;

    if( ( ret = mbedtls_pk_write_pubkey_der( key, output_buf,
                                     sizeof(output_buf) ) ) < 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_PUBLIC_KEY, PEM_END_PUBLIC_KEY,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int mbedtls_pk_write_key_pem( mbedtls_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char output_buf[PRV_DER_MAX_BYTES];
    const char *begin, *end;
    size_t olen = 0;

    if( ( ret = mbedtls_pk_write_key_der( key, output_buf, sizeof(output_buf) ) ) < 0 )
        return( ret );

#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_RSA )
    {
        begin = PEM_BEGIN_PRIVATE_KEY_RSA;
        end = PEM_END_PRIVATE_KEY_RSA;
    }
    else
#endif
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( key ) == MBEDTLS_PK_ECKEY )
    {
        begin = PEM_BEGIN_PRIVATE_KEY_EC;
        end = PEM_END_PRIVATE_KEY_EC;
    }
    else
#endif
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    if( ( ret = mbedtls_pem_write_buffer( begin, end,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

#if defined(MBEDTLS_PK_WRITE_PKCS8_C)
int mbedtls_pk_write_key_pkcs8_pem( mbedtls_pk_context *key, unsigned char *buf, size_t size,
                                  const unsigned char *pwd, size_t pwdlen,
                                  const unsigned char *pbe, size_t pbelen )
{
    int ret;
    unsigned char output_buf[PRV_DER_MAX_BYTES];
    const char *begin, *end;
    size_t olen = 0;

    if( ( ret = mbedtls_pk_write_key_pkcs8_der( key, output_buf, sizeof(output_buf),
                                                pwd, pwdlen, pbe, pbelen ) ) < 0 )
        return( ret );

    if (pwd != NULL && pwdlen > 0)
    {
        begin = PEM_BEGIN_ENC_PRIVATE_KEY;
        end = PEM_END_ENC_PRIVATE_KEY;
    }
    else
    {
        begin = PEM_BEGIN_PRIVATE_KEY;
        end = PEM_END_PRIVATE_KEY;
    }

    if( ( ret = mbedtls_pem_write_buffer( begin, end,
                                          output_buf + sizeof(output_buf) - ret,
                                          ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_PK_WRITE_PKCS8_C */
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_PK_WRITE_C */
