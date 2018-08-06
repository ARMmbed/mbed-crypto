/**
 * \file pk.h
 *
 * \brief Public Key abstraction layer
 */
/*
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
 *  This file is part of Mbed Crypto (https://tls.mbed.org)
 */

#ifndef MBEDCRYPTO_PK_H
#define MBEDCRYPTO_PK_H

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#include "md.h"

#if defined(MBEDCRYPTO_RSA_C)
#include "rsa.h"
#endif

#if defined(MBEDCRYPTO_ECP_C)
#include "ecp.h"
#endif

#if defined(MBEDCRYPTO_ECDSA_C)
#include "ecdsa.h"
#endif

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#define MBEDCRYPTO_ERR_PK_ALLOC_FAILED        -0x3F80  /**< Memory allocation failed. */
#define MBEDCRYPTO_ERR_PK_TYPE_MISMATCH       -0x3F00  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
#define MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA      -0x3E80  /**< Bad input parameters to function. */
#define MBEDCRYPTO_ERR_PK_FILE_IO_ERROR       -0x3E00  /**< Read/write of file failed. */
#define MBEDCRYPTO_ERR_PK_KEY_INVALID_VERSION -0x3D80  /**< Unsupported key version */
#define MBEDCRYPTO_ERR_PK_KEY_INVALID_FORMAT  -0x3D00  /**< Invalid key tag or value. */
#define MBEDCRYPTO_ERR_PK_UNKNOWN_PK_ALG      -0x3C80  /**< Key algorithm is unsupported (only RSA and EC are supported). */
#define MBEDCRYPTO_ERR_PK_PASSWORD_REQUIRED   -0x3C00  /**< Private key password can't be empty. */
#define MBEDCRYPTO_ERR_PK_PASSWORD_MISMATCH   -0x3B80  /**< Given private key password does not allow for correct decryption. */
#define MBEDCRYPTO_ERR_PK_INVALID_PUBKEY      -0x3B00  /**< The pubkey tag or value is invalid (only RSA and EC are supported). */
#define MBEDCRYPTO_ERR_PK_INVALID_ALG         -0x3A80  /**< The algorithm tag or value is invalid. */
#define MBEDCRYPTO_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00  /**< Elliptic curve is unsupported (only NIST curves are supported). */
#define MBEDCRYPTO_ERR_PK_FEATURE_UNAVAILABLE -0x3980  /**< Unavailable feature, e.g. RSA disabled for RSA key. */
#define MBEDCRYPTO_ERR_PK_SIG_LEN_MISMATCH    -0x3900  /**< The buffer contains a valid signature followed by more data. */
#define MBEDCRYPTO_ERR_PK_HW_ACCEL_FAILED     -0x3880  /**< PK hardware accelerator failed. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Public key types
 */
typedef enum {
    MBEDCRYPTO_PK_NONE=0,
    MBEDCRYPTO_PK_RSA,
    MBEDCRYPTO_PK_ECKEY,
    MBEDCRYPTO_PK_ECKEY_DH,
    MBEDCRYPTO_PK_ECDSA,
    MBEDCRYPTO_PK_RSA_ALT,
    MBEDCRYPTO_PK_RSASSA_PSS,
} mbedcrypto_pk_type_t;

/**
 * \brief           Options for RSASSA-PSS signature verification.
 *                  See \c mbedcrypto_rsa_rsassa_pss_verify_ext()
 */
typedef struct
{
    mbedcrypto_md_type_t mgf1_hash_id;
    int expected_salt_len;

} mbedcrypto_pk_rsassa_pss_options;

/**
 * \brief           Types for interfacing with the debug module
 */
typedef enum
{
    MBEDCRYPTO_PK_DEBUG_NONE = 0,
    MBEDCRYPTO_PK_DEBUG_MPI,
    MBEDCRYPTO_PK_DEBUG_ECP,
} mbedcrypto_pk_debug_type;

/**
 * \brief           Item to send to the debug module
 */
typedef struct
{
    mbedcrypto_pk_debug_type type;
    const char *name;
    void *value;
} mbedcrypto_pk_debug_item;

/** Maximum number of item send for debugging, plus 1 */
#define MBEDCRYPTO_PK_DEBUG_MAX_ITEMS 3

/**
 * \brief           Public key information and operations
 */
typedef struct mbedcrypto_pk_info_t mbedcrypto_pk_info_t;

/**
 * \brief           Public key container
 */
typedef struct
{
    const mbedcrypto_pk_info_t *   pk_info; /**< Public key informations        */
    void *                      pk_ctx;  /**< Underlying public key context  */
} mbedcrypto_pk_context;

#if defined(MBEDCRYPTO_RSA_C)
/**
 * Quick access to an RSA context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an RSA context
 * before using this function!
 */
static inline mbedcrypto_rsa_context *mbedcrypto_pk_rsa( const mbedcrypto_pk_context pk )
{
    return( (mbedcrypto_rsa_context *) (pk).pk_ctx );
}
#endif /* MBEDCRYPTO_RSA_C */

#if defined(MBEDCRYPTO_ECP_C)
/**
 * Quick access to an EC context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an EC context
 * before using this function!
 */
static inline mbedcrypto_ecp_keypair *mbedcrypto_pk_ec( const mbedcrypto_pk_context pk )
{
    return( (mbedcrypto_ecp_keypair *) (pk).pk_ctx );
}
#endif /* MBEDCRYPTO_ECP_C */

#if defined(MBEDCRYPTO_PK_RSA_ALT_SUPPORT)
/**
 * \brief           Types for RSA-alt abstraction
 */
typedef int (*mbedcrypto_pk_rsa_alt_decrypt_func)( void *ctx, int mode, size_t *olen,
                    const unsigned char *input, unsigned char *output,
                    size_t output_max_len );
typedef int (*mbedcrypto_pk_rsa_alt_sign_func)( void *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                    int mode, mbedcrypto_md_type_t md_alg, unsigned int hashlen,
                    const unsigned char *hash, unsigned char *sig );
typedef size_t (*mbedcrypto_pk_rsa_alt_key_len_func)( void *ctx );
#endif /* MBEDCRYPTO_PK_RSA_ALT_SUPPORT */

/**
 * \brief           Return information associated with the given PK type
 *
 * \param pk_type   PK type to search for.
 *
 * \return          The PK info associated with the type or NULL if not found.
 */
const mbedcrypto_pk_info_t *mbedcrypto_pk_info_from_type( mbedcrypto_pk_type_t pk_type );

/**
 * \brief           Initialize a mbedcrypto_pk_context (as NONE)
 */
void mbedcrypto_pk_init( mbedcrypto_pk_context *ctx );

/**
 * \brief           Free a mbedcrypto_pk_context
 */
void mbedcrypto_pk_free( mbedcrypto_pk_context *ctx );

/**
 * \brief           Initialize a PK context with the information given
 *                  and allocates the type-specific PK subcontext.
 *
 * \param ctx       Context to initialize. Must be empty (type NONE).
 * \param info      Information to use
 *
 * \return          0 on success,
 *                  MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA on invalid input,
 *                  MBEDCRYPTO_ERR_PK_ALLOC_FAILED on allocation failure.
 *
 * \note            For contexts holding an RSA-alt key, use
 *                  \c mbedcrypto_pk_setup_rsa_alt() instead.
 */
int mbedcrypto_pk_setup( mbedcrypto_pk_context *ctx, const mbedcrypto_pk_info_t *info );

#if defined(MBEDCRYPTO_PK_RSA_ALT_SUPPORT)
/**
 * \brief           Initialize an RSA-alt context
 *
 * \param ctx       Context to initialize. Must be empty (type NONE).
 * \param key       RSA key pointer
 * \param decrypt_func  Decryption function
 * \param sign_func     Signing function
 * \param key_len_func  Function returning key length in bytes
 *
 * \return          0 on success, or MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA if the
 *                  context wasn't already initialized as RSA_ALT.
 *
 * \note            This function replaces \c mbedcrypto_pk_setup() for RSA-alt.
 */
int mbedcrypto_pk_setup_rsa_alt( mbedcrypto_pk_context *ctx, void * key,
                         mbedcrypto_pk_rsa_alt_decrypt_func decrypt_func,
                         mbedcrypto_pk_rsa_alt_sign_func sign_func,
                         mbedcrypto_pk_rsa_alt_key_len_func key_len_func );
#endif /* MBEDCRYPTO_PK_RSA_ALT_SUPPORT */

/**
 * \brief           Get the size in bits of the underlying key
 *
 * \param ctx       Context to use
 *
 * \return          Key size in bits, or 0 on error
 */
size_t mbedcrypto_pk_get_bitlen( const mbedcrypto_pk_context *ctx );

/**
 * \brief           Get the length in bytes of the underlying key
 * \param ctx       Context to use
 *
 * \return          Key length in bytes, or 0 on error
 */
static inline size_t mbedcrypto_pk_get_len( const mbedcrypto_pk_context *ctx )
{
    return( ( mbedcrypto_pk_get_bitlen( ctx ) + 7 ) / 8 );
}

/**
 * \brief           Tell if a context can do the operation given by type
 *
 * \param ctx       Context to test
 * \param type      Target type
 *
 * \return          0 if context can't do the operations,
 *                  1 otherwise.
 */
int mbedcrypto_pk_can_do( const mbedcrypto_pk_context *ctx, mbedcrypto_pk_type_t type );

/**
 * \brief           Verify signature (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  #MBEDCRYPTO_ERR_PK_SIG_LEN_MISMATCH if there is a valid
 *                  signature in sig but its length is less than \p siglen,
 *                  or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  Use \c mbedcrypto_pk_verify_ext( MBEDCRYPTO_PK_RSASSA_PSS, ... )
 *                  to verify RSASSA_PSS signatures.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be MBEDCRYPTO_MD_NONE, only if hash_len != 0
 */
int mbedcrypto_pk_verify( mbedcrypto_pk_context *ctx, mbedcrypto_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len );

/**
 * \brief           Verify signature, with options.
 *                  (Includes verification of the padding depending on type.)
 *
 * \param type      Signature type (inc. possible padding type) to verify
 * \param options   Pointer to type-specific options, or NULL
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  #MBEDCRYPTO_ERR_PK_TYPE_MISMATCH if the PK context can't be
 *                  used for this type of signatures,
 *                  #MBEDCRYPTO_ERR_PK_SIG_LEN_MISMATCH if there is a valid
 *                  signature in sig but its length is less than \p siglen,
 *                  or a specific error code.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be MBEDCRYPTO_MD_NONE, only if hash_len != 0
 *
 * \note            If type is MBEDCRYPTO_PK_RSASSA_PSS, then options must point
 *                  to a mbedcrypto_pk_rsassa_pss_options structure,
 *                  otherwise it must be NULL.
 */
int mbedcrypto_pk_verify_ext( mbedcrypto_pk_type_t type, const void *options,
                   mbedcrypto_pk_context *ctx, mbedcrypto_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len );

/**
 * \brief           Make signature, including padding if relevant.
 *
 * \param ctx       PK context to use - must hold a private key
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Place to write the signature
 * \param sig_len   Number of bytes written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  There is no interface in the PK module to make RSASSA-PSS
 *                  signatures yet.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            For RSA, md_alg may be MBEDCRYPTO_MD_NONE if hash_len != 0.
 *                  For ECDSA, md_alg may never be MBEDCRYPTO_MD_NONE.
 */
int mbedcrypto_pk_sign( mbedcrypto_pk_context *ctx, mbedcrypto_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Decrypt message (including padding if relevant).
 *
 * \param ctx       PK context to use - must hold a private key
 * \param input     Input to decrypt
 * \param ilen      Input size
 * \param output    Decrypted output
 * \param olen      Decrypted message length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
int mbedcrypto_pk_decrypt( mbedcrypto_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Encrypt message (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param input     Message to encrypt
 * \param ilen      Message size
 * \param output    Encrypted output
 * \param olen      Encrypted output length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a specific error code.
 */
int mbedcrypto_pk_encrypt( mbedcrypto_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Check if a public-private pair of keys matches.
 *
 * \param pub       Context holding a public key.
 * \param prv       Context holding a private (and public) key.
 *
 * \return          0 on success or MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA
 */
int mbedcrypto_pk_check_pair( const mbedcrypto_pk_context *pub, const mbedcrypto_pk_context *prv );

/**
 * \brief           Export debug information
 *
 * \param ctx       Context to use
 * \param items     Place to write debug items
 *
 * \return          0 on success or MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA
 */
int mbedcrypto_pk_debug( const mbedcrypto_pk_context *ctx, mbedcrypto_pk_debug_item *items );

/**
 * \brief           Access the type name
 *
 * \param ctx       Context to use
 *
 * \return          Type name on success, or "invalid PK"
 */
const char * mbedcrypto_pk_get_name( const mbedcrypto_pk_context *ctx );

/**
 * \brief           Get the key type
 *
 * \param ctx       Context to use
 *
 * \return          Type on success, or MBEDCRYPTO_PK_NONE
 */
mbedcrypto_pk_type_t mbedcrypto_pk_get_type( const mbedcrypto_pk_context *ctx );

#if defined(MBEDCRYPTO_PK_PARSE_C)
/** \ingroup pk_module */
/**
 * \brief           Parse a private key in PEM or DER format
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *                  (including the terminating null byte for PEM data)
 * \param pwd       password for decryption (optional)
 * \param pwdlen    size of the password
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedcrypto_pk_init() or reset with mbedcrypto_pk_free(). If you need a
 *                  specific key type, check the result with mbedcrypto_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedcrypto_pk_parse_key( mbedcrypto_pk_context *ctx,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen );

/** \ingroup pk_module */
/**
 * \brief           Parse a public key in PEM or DER format
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *                  (including the terminating null byte for PEM data)
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedcrypto_pk_init() or reset with mbedcrypto_pk_free(). If you need a
 *                  specific key type, check the result with mbedcrypto_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedcrypto_pk_parse_public_key( mbedcrypto_pk_context *ctx,
                         const unsigned char *key, size_t keylen );

#if defined(MBEDCRYPTO_FS_IO)
/** \ingroup pk_module */
/**
 * \brief           Load and parse a private key
 *
 * \param ctx       key to be initialized
 * \param path      filename to read the private key from
 * \param password  password to decrypt the file (can be NULL)
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedcrypto_pk_init() or reset with mbedcrypto_pk_free(). If you need a
 *                  specific key type, check the result with mbedcrypto_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedcrypto_pk_parse_keyfile( mbedcrypto_pk_context *ctx,
                      const char *path, const char *password );

/** \ingroup pk_module */
/**
 * \brief           Load and parse a public key
 *
 * \param ctx       key to be initialized
 * \param path      filename to read the public key from
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedcrypto_pk_init() or reset with mbedcrypto_pk_free(). If
 *                  you need a specific key type, check the result with
 *                  mbedcrypto_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedcrypto_pk_parse_public_keyfile( mbedcrypto_pk_context *ctx, const char *path );
#endif /* MBEDCRYPTO_FS_IO */
#endif /* MBEDCRYPTO_PK_PARSE_C */

#if defined(MBEDCRYPTO_PK_WRITE_C)
/**
 * \brief           Write a private key to a PKCS#1 or SEC1 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedcrypto_pk_write_key_der( mbedcrypto_pk_context *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a public key to a SubjectPublicKeyInfo DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedcrypto_pk_write_pubkey_der( mbedcrypto_pk_context *ctx, unsigned char *buf, size_t size );

#if defined(MBEDCRYPTO_PEM_WRITE_C)
/**
 * \brief           Write a public key to a PEM string
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 if successful, or a specific error code
 */
int mbedcrypto_pk_write_pubkey_pem( mbedcrypto_pk_context *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a private key to a PKCS#1 or SEC1 PEM string
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 if successful, or a specific error code
 */
int mbedcrypto_pk_write_key_pem( mbedcrypto_pk_context *ctx, unsigned char *buf, size_t size );
#endif /* MBEDCRYPTO_PEM_WRITE_C */
#endif /* MBEDCRYPTO_PK_WRITE_C */

/*
 * WARNING: Low-level functions. You probably do not want to use these unless
 *          you are certain you do ;)
 */

#if defined(MBEDCRYPTO_PK_PARSE_C)
/**
 * \brief           Parse a SubjectPublicKeyInfo DER structure
 *
 * \param p         the position in the ASN.1 data
 * \param end       end of the buffer
 * \param pk        the key to fill
 *
 * \return          0 if successful, or a specific PK error code
 */
int mbedcrypto_pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        mbedcrypto_pk_context *pk );
#endif /* MBEDCRYPTO_PK_PARSE_C */

#if defined(MBEDCRYPTO_PK_WRITE_C)
/**
 * \brief           Write a subjectPublicKey to ASN.1 data
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param key       public key to write away
 *
 * \return          the length written or a negative error code
 */
int mbedcrypto_pk_write_pubkey( unsigned char **p, unsigned char *start,
                     const mbedcrypto_pk_context *key );
#endif /* MBEDCRYPTO_PK_WRITE_C */

/*
 * Internal module functions. You probably do not want to use these unless you
 * know you do.
 */
#if defined(MBEDCRYPTO_FS_IO)
int mbedcrypto_pk_load_file( const char *path, unsigned char **buf, size_t *n );
#endif

#ifdef __cplusplus
}
#endif

#endif /* MBEDCRYPTO_PK_H */
