/*
 *  Public Key abstraction layer
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
 *  This file is part of Mbed Crypto (https://tls.mbed.org)
 */

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "mbedcrypto/config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#if defined(MBEDCRYPTO_PK_C)
#include "mbedcrypto/pk.h"
#include "mbedcrypto/pk_internal.h"

#include "mbedcrypto/platform_util.h"

#if defined(MBEDCRYPTO_RSA_C)
#include "mbedcrypto/rsa.h"
#endif
#if defined(MBEDCRYPTO_ECP_C)
#include "mbedcrypto/ecp.h"
#endif
#if defined(MBEDCRYPTO_ECDSA_C)
#include "mbedcrypto/ecdsa.h"
#endif

#include <limits.h>
#include <stdint.h>

/*
 * Initialise a mbedcrypto_pk_context
 */
void mbedcrypto_pk_init( mbedcrypto_pk_context *ctx )
{
    if( ctx == NULL )
        return;

    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

/*
 * Free (the components of) a mbedcrypto_pk_context
 */
void mbedcrypto_pk_free( mbedcrypto_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return;

    ctx->pk_info->ctx_free_func( ctx->pk_ctx );

    mbedcrypto_platform_zeroize( ctx, sizeof( mbedcrypto_pk_context ) );
}

/*
 * Get pk_info structure from type
 */
const mbedcrypto_pk_info_t * mbedcrypto_pk_info_from_type( mbedcrypto_pk_type_t pk_type )
{
    switch( pk_type ) {
#if defined(MBEDCRYPTO_RSA_C)
        case MBEDCRYPTO_PK_RSA:
            return( &mbedcrypto_rsa_info );
#endif
#if defined(MBEDCRYPTO_ECP_C)
        case MBEDCRYPTO_PK_ECKEY:
            return( &mbedcrypto_eckey_info );
        case MBEDCRYPTO_PK_ECKEY_DH:
            return( &mbedcrypto_eckeydh_info );
#endif
#if defined(MBEDCRYPTO_ECDSA_C)
        case MBEDCRYPTO_PK_ECDSA:
            return( &mbedcrypto_ecdsa_info );
#endif
        /* MBEDCRYPTO_PK_RSA_ALT omitted on purpose */
        default:
            return( NULL );
    }
}

/*
 * Initialise context
 */
int mbedcrypto_pk_setup( mbedcrypto_pk_context *ctx, const mbedcrypto_pk_info_t *info )
{
    if( ctx == NULL || info == NULL || ctx->pk_info != NULL )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDCRYPTO_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    return( 0 );
}

#if defined(MBEDCRYPTO_PK_RSA_ALT_SUPPORT)
/*
 * Initialize an RSA-alt context
 */
int mbedcrypto_pk_setup_rsa_alt( mbedcrypto_pk_context *ctx, void * key,
                         mbedcrypto_pk_rsa_alt_decrypt_func decrypt_func,
                         mbedcrypto_pk_rsa_alt_sign_func sign_func,
                         mbedcrypto_pk_rsa_alt_key_len_func key_len_func )
{
    mbedcrypto_rsa_alt_context *rsa_alt;
    const mbedcrypto_pk_info_t *info = &mbedcrypto_rsa_alt_info;

    if( ctx == NULL || ctx->pk_info != NULL )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDCRYPTO_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    rsa_alt = (mbedcrypto_rsa_alt_context *) ctx->pk_ctx;

    rsa_alt->key = key;
    rsa_alt->decrypt_func = decrypt_func;
    rsa_alt->sign_func = sign_func;
    rsa_alt->key_len_func = key_len_func;

    return( 0 );
}
#endif /* MBEDCRYPTO_PK_RSA_ALT_SUPPORT */

/*
 * Tell if a PK can do the operations of the given type
 */
int mbedcrypto_pk_can_do( const mbedcrypto_pk_context *ctx, mbedcrypto_pk_type_t type )
{
    /* null or NONE context can't do anything */
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->can_do( type ) );
}

/*
 * Helper for mbedcrypto_pk_sign and mbedcrypto_pk_verify
 */
static inline int pk_hashlen_helper( mbedcrypto_md_type_t md_alg, size_t *hash_len )
{
    const mbedcrypto_md_info_t *md_info;

    if( *hash_len != 0 )
        return( 0 );

    if( ( md_info = mbedcrypto_md_info_from_type( md_alg ) ) == NULL )
        return( -1 );

    *hash_len = mbedcrypto_md_get_size( md_info );
    return( 0 );
}

/*
 * Verify a signature
 */
int mbedcrypto_pk_verify( mbedcrypto_pk_context *ctx, mbedcrypto_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->verify_func == NULL )
        return( MBEDCRYPTO_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->verify_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                       sig, sig_len ) );
}

/*
 * Verify a signature with options
 */
int mbedcrypto_pk_verify_ext( mbedcrypto_pk_type_t type, const void *options,
                   mbedcrypto_pk_context *ctx, mbedcrypto_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    if( ! mbedcrypto_pk_can_do( ctx, type ) )
        return( MBEDCRYPTO_ERR_PK_TYPE_MISMATCH );

    if( type == MBEDCRYPTO_PK_RSASSA_PSS )
    {
#if defined(MBEDCRYPTO_RSA_C) && defined(MBEDCRYPTO_PKCS1_V21)
        int ret;
        const mbedcrypto_pk_rsassa_pss_options *pss_opts;

#if SIZE_MAX > UINT_MAX
        if( md_alg == MBEDCRYPTO_MD_NONE && UINT_MAX < hash_len )
            return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

        if( options == NULL )
            return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

        pss_opts = (const mbedcrypto_pk_rsassa_pss_options *) options;

        if( sig_len < mbedcrypto_pk_get_len( ctx ) )
            return( MBEDCRYPTO_ERR_RSA_VERIFY_FAILED );

        ret = mbedcrypto_rsa_rsassa_pss_verify_ext( mbedcrypto_pk_rsa( *ctx ),
                NULL, NULL, MBEDCRYPTO_RSA_PUBLIC,
                md_alg, (unsigned int) hash_len, hash,
                pss_opts->mgf1_hash_id,
                pss_opts->expected_salt_len,
                sig );
        if( ret != 0 )
            return( ret );

        if( sig_len > mbedcrypto_pk_get_len( ctx ) )
            return( MBEDCRYPTO_ERR_PK_SIG_LEN_MISMATCH );

        return( 0 );
#else
        return( MBEDCRYPTO_ERR_PK_FEATURE_UNAVAILABLE );
#endif /* MBEDCRYPTO_RSA_C && MBEDCRYPTO_PKCS1_V21 */
    }

    /* General case: no options */
    if( options != NULL )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    return( mbedcrypto_pk_verify( ctx, md_alg, hash, hash_len, sig, sig_len ) );
}

/*
 * Make a signature
 */
int mbedcrypto_pk_sign( mbedcrypto_pk_context *ctx, mbedcrypto_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->sign_func == NULL )
        return( MBEDCRYPTO_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->sign_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                     sig, sig_len, f_rng, p_rng ) );
}

/*
 * Decrypt message
 */
int mbedcrypto_pk_decrypt( mbedcrypto_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->decrypt_func == NULL )
        return( MBEDCRYPTO_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->decrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}

/*
 * Encrypt message
 */
int mbedcrypto_pk_encrypt( mbedcrypto_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->encrypt_func == NULL )
        return( MBEDCRYPTO_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->encrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}

/*
 * Check public-private key pair
 */
int mbedcrypto_pk_check_pair( const mbedcrypto_pk_context *pub, const mbedcrypto_pk_context *prv )
{
    if( pub == NULL || pub->pk_info == NULL ||
        prv == NULL || prv->pk_info == NULL ||
        prv->pk_info->check_pair_func == NULL )
    {
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );
    }

    if( prv->pk_info->type == MBEDCRYPTO_PK_RSA_ALT )
    {
        if( pub->pk_info->type != MBEDCRYPTO_PK_RSA )
            return( MBEDCRYPTO_ERR_PK_TYPE_MISMATCH );
    }
    else
    {
        if( pub->pk_info != prv->pk_info )
            return( MBEDCRYPTO_ERR_PK_TYPE_MISMATCH );
    }

    return( prv->pk_info->check_pair_func( pub->pk_ctx, prv->pk_ctx ) );
}

/*
 * Get key size in bits
 */
size_t mbedcrypto_pk_get_bitlen( const mbedcrypto_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->get_bitlen( ctx->pk_ctx ) );
}

/*
 * Export debug information
 */
int mbedcrypto_pk_debug( const mbedcrypto_pk_context *ctx, mbedcrypto_pk_debug_item *items )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->debug_func == NULL )
        return( MBEDCRYPTO_ERR_PK_TYPE_MISMATCH );

    ctx->pk_info->debug_func( ctx->pk_ctx, items );
    return( 0 );
}

/*
 * Access the PK type name
 */
const char *mbedcrypto_pk_get_name( const mbedcrypto_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( "invalid PK" );

    return( ctx->pk_info->name );
}

/*
 * Access the PK type
 */
mbedcrypto_pk_type_t mbedcrypto_pk_get_type( const mbedcrypto_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDCRYPTO_PK_NONE );

    return( ctx->pk_info->type );
}

#endif /* MBEDCRYPTO_PK_C */
