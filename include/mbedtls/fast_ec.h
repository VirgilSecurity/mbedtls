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

#ifndef MBEDTLS_FAST_EC_H
#define MBEDTLS_FAST_EC_H

#include <stdlib.h>

/*
 * Fast EC error codes
 */
#define MBEDTLS_ERR_FAST_EC_ALLOC_FAILED             -0x4980  /**< Failed to allocate memory. */
#define MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA           -0x4900  /**< Bad input parameters. */
#define MBEDTLS_ERR_FAST_EC_VERIFY_FAILED            -0x4880  /**< The signature is not valid. */
#define MBEDTLS_ERR_FAST_EC_SIG_LEN_MISMATCH         -0x4800  /**< The signature length mismatch. */
#define MBEDTLS_ERR_FAST_EC_FEATURE_UNAVAILABLE      -0x4780  /**< The selected feature is not available. */
#define MBEDTLS_ERR_FAST_EC_PUB_PRV_MISMATCH         -0x4700  /**< Public key is not match private key. */
#define MBEDTLS_ERR_FAST_EC_SHARED_WEAK_KEY          -0x4680  /**< Key contains point of small order. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MBEDTLS_FAST_EC_NONE = 0,  /**< Not Defined */
    MBEDTLS_FAST_EC_X25519,    /**< Curve25519 */
    MBEDTLS_FAST_EC_ED25519,   /**< Ed25519 */
} mbedtls_fast_ec_type_t;

/*
 * Opaque struct defined in fast_ec_internal.h
 */
typedef struct mbedtls_fast_ec_info_t mbedtls_fast_ec_info_t;

/*
 * Fast EC keypair structure.
 */
typedef struct {
    const mbedtls_fast_ec_info_t* info;   /**< Keys details */
    unsigned char *public_key;            /**< Public key */
    unsigned char *private_key;           /**< Private key */
} mbedtls_fast_ec_keypair_t;

/**
 * \brief           Returns the Fast EC information associated with the type
 *
 * \param type      type of the specific Fast EC algorithm.
 *
 * \return          The Fast EC information associated with type or
 *                  NULL if not found.
 */
const mbedtls_fast_ec_info_t* mbedtls_fast_ec_info_from_type( mbedtls_fast_ec_type_t type );

/**
 * \brief           Initialize a keypair (as NONE)
 *                  This should always be called first.
 *                  Prepares the context for mbedtls_fast_ec_setup() or mbedtls_fast_ec_free().
 */
void mbedtls_fast_ec_init( mbedtls_fast_ec_keypair_t *keypair );

/**
 * \brief           Free and clear the internal structures of keypair.
 *                  Can be called at any time after mbedtls_fast_ec_init().
 *                  Mandatory once mbedtls_fast_ec_setup() has been called.
 */
void mbedtls_fast_ec_free( mbedtls_fast_ec_keypair_t *keypair);

/**
 * \brief           Select Fast EC to use and allocate internal structures.
 *                  Should be called after mbedtls_fast_ec_init() or mbedtls_fast_ec_free().
 *                  Makes it necessary to call mbedtls_fast_ec_free() later.
 *
 * \param keypair   Context to set up.
 * \param info      Fast EC algorithm to use.
 *
 * \returns         \c 0 on success,
 *                  \c MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA on parameter failure,
 *                  \c MBEDTLS_ERR_FAST_EC_ALLOC_FAILED memory allocation failure.
 */
int mbedtls_fast_ec_setup( mbedtls_fast_ec_keypair_t *keypair, const mbedtls_fast_ec_info_t* info );

/**
 * \brief           Generate a keypair
 *                  Generate based on the setup information.
 *                  Should be called after mbedtls_fast_ec_setup().
 *
 * \param keypair   Destination keypair.
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_FAST_EC_XXX.
 */
int mbedtls_fast_ec_gen_key( mbedtls_fast_ec_keypair_t *keypair,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );


/**
 * \brief           Compute public key based on the private key in context
 *
 * \param keypair   Keypair structure holding at least private key
 *
 * \return          0 if successful (keys are valid and match), or
 *                  MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA.
 */
int mbedtls_fast_ec_compute_pub( mbedtls_fast_ec_keypair_t *keypair );

/**
 * \brief           Compute EdDSA signature of a given message
 *
 * \param keypair   Fast EC private context
 * \param sig       Produced signature
 * \param sig_len   Signature actual length
 * \param data      Data to be signed
 * \param data_len  Data length
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_FAST_EC_XXX.
 */
int mbedtls_fast_ec_sign( const mbedtls_fast_ec_keypair_t* keypair,
                unsigned char* sig, size_t *sig_len,
                const unsigned char* data, size_t data_len );

/**
 * \brief           Verify EdDSA signature of a given message
 *
 * \param keypair   Fast EC public context
 * \param sig       Signature
 * \param sig_len   Signature length
 * \param data      Data to be verified
 * \param data_len  Data length
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_FAST_EC_XXX.
 */
int mbedtls_fast_ec_verify( const mbedtls_fast_ec_keypair_t* keypair,
                const unsigned char* sig, size_t sig_len,
                const unsigned char* data, size_t data_len);

/**
 * \brief               Compute shared secret
 *
 * \param pub           Fast EC public context
 * \param prv           Fast EC private context
 * \param shared        Derived secret key
 * \param shared_len    Secret key length
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_FAST_EC_XXX.
 *
 */
int mbedtls_fast_ec_compute_shared(
                const mbedtls_fast_ec_keypair_t* pub, const mbedtls_fast_ec_keypair_t* prv,
                unsigned char* shared, size_t shared_len );

/**
 * \brief         Copy the contents of keypaur src into dst
 *
 * \param dst     Destination keypair
 * \param src     Source keypair
 *
 * \return          0 if successful, or
 *                  MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA if dst is already defined, or
 *                  MBEDTLS_ERR_FAST_EC_ALLOC_FAILED if memory allocation failed.
 */
int mbedtls_fast_ec_copy(mbedtls_fast_ec_keypair_t* dst, const mbedtls_fast_ec_keypair_t* src);

/**
 * \brief           Check a public-private key pair
 *
 * \param pub       Keypair structure holding a public key
 * \param prv       Keypair structure holding a private key
 *
 * \return          0 if successful (keys are valid and match), or
 *                  MBEDTLS_ERR_FAST_EC_BAD_INPUT_DATA, or
 *                  MBEDTLS_ERR_FAST_EC_ALLOC_FAILED, or
 *                  MBEDTLS_ERR_FAST_EC_PUB_PRV_MISMATCH.
 */
int mbedtls_fast_ec_check_pub_priv( const mbedtls_fast_ec_keypair_t *pub, const mbedtls_fast_ec_keypair_t *prv );

/**
 * \brief           Returns the type of the Fast EC algorithm type.
 *
 * \param info      Fast EC info
 *
 * \return          type of the Fast EC algorithm type.
 */
mbedtls_fast_ec_type_t mbedtls_fast_ec_get_type( const mbedtls_fast_ec_info_t* info );

/**
 * \brief           Returns the name of the Fast EC algorithm type.
 *
 * \param info      Fast EC info
 *
 * \return          name of the Fast EC algorithm type.
 */
const char* mbedtls_fast_ec_get_name( const mbedtls_fast_ec_info_t* info );

/**
 * \brief           Returns the length in bits of the Fast EC key.
 *
 * \param info      Fast EC info
 *
 * \return          length in bits of the Fast EC key.
 */
size_t mbedtls_fast_ec_get_key_bitlen( const mbedtls_fast_ec_info_t* info );

/**
 * \brief           Returns the length in bytes of the Fast EC key.
 *
 * \param info      Fast EC info
 *
 * \return          length in bytes of the Fast EC key.
 */
size_t mbedtls_fast_ec_get_key_len( const mbedtls_fast_ec_info_t* info );

/**
 * \brief           Returns the length in bytes of the Fast EC signature.
 *
 * \param info      Fast EC info
 *
 * \return          length in bytes of the Fast EC signature.
 */
size_t mbedtls_fast_ec_get_sig_len( const mbedtls_fast_ec_info_t* info );

/**
 * \brief           Returns the length in bytes of the Fast EC derived shared key.
 *
 * \param info      Fast EC info
 *
 * \return          length in bytes of the Fast EC derived shared key.
 */
size_t mbedtls_fast_ec_get_shared_len( const mbedtls_fast_ec_info_t* info );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_FAST_EC_H */
