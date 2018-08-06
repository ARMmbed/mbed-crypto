/*
 *  Public Key abstraction layer: wrapper functions
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
#include "mbedcrypto/pk_internal.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "mbedcrypto/rsa.h"

#include <string.h>

#if defined(MBEDCRYPTO_ECP_C)
#include "mbedcrypto/ecp.h"
#endif

#if defined(MBEDCRYPTO_ECDSA_C)
#include "mbedcrypto/ecdsa.h"
#endif

#if defined(MBEDCRYPTO_PK_RSA_ALT_SUPPORT)
#include "mbedcrypto/platform_util.h"
#endif

#if defined(MBEDCRYPTO_PLATFORM_C)
#include "mbedcrypto/platform.h"
#else
#include <stdlib.h>
#define mbedcrypto_calloc    calloc
#define mbedcrypto_free       free
#endif

#include <limits.h>
#include <stdint.h>

#if defined(MBEDCRYPTO_RSA_C)
static int rsa_can_do( mbedcrypto_pk_type_t type )
{
    return( type == MBEDCRYPTO_PK_RSA ||
            type == MBEDCRYPTO_PK_RSASSA_PSS );
}

static size_t rsa_get_bitlen( const void *ctx )
{
    const mbedcrypto_rsa_context * rsa = (const mbedcrypto_rsa_context *) ctx;
    return( mbedcrypto_rsa_get_bitlen( rsa ) );
}

static int rsa_verify_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    int ret;
    mbedcrypto_rsa_context * rsa = (mbedcrypto_rsa_context *) ctx;
    size_t rsa_len = mbedcrypto_rsa_get_len( rsa );

#if SIZE_MAX > UINT_MAX
    if( md_alg == MBEDCRYPTO_MD_NONE && UINT_MAX < hash_len )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    if( sig_len < rsa_len )
        return( MBEDCRYPTO_ERR_RSA_VERIFY_FAILED );

    if( ( ret = mbedcrypto_rsa_pkcs1_verify( rsa, NULL, NULL,
                                  MBEDCRYPTO_RSA_PUBLIC, md_alg,
                                  (unsigned int) hash_len, hash, sig ) ) != 0 )
        return( ret );

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use mbedcrypto_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    if( sig_len > rsa_len )
        return( MBEDCRYPTO_ERR_PK_SIG_LEN_MISMATCH );

    return( 0 );
}

static int rsa_sign_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedcrypto_rsa_context * rsa = (mbedcrypto_rsa_context *) ctx;

#if SIZE_MAX > UINT_MAX
    if( md_alg == MBEDCRYPTO_MD_NONE && UINT_MAX < hash_len )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    *sig_len = mbedcrypto_rsa_get_len( rsa );

    return( mbedcrypto_rsa_pkcs1_sign( rsa, f_rng, p_rng, MBEDCRYPTO_RSA_PRIVATE,
                md_alg, (unsigned int) hash_len, hash, sig ) );
}

static int rsa_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedcrypto_rsa_context * rsa = (mbedcrypto_rsa_context *) ctx;

    if( ilen != mbedcrypto_rsa_get_len( rsa ) )
        return( MBEDCRYPTO_ERR_RSA_BAD_INPUT_DATA );

    return( mbedcrypto_rsa_pkcs1_decrypt( rsa, f_rng, p_rng,
                MBEDCRYPTO_RSA_PRIVATE, olen, input, output, osize ) );
}

static int rsa_encrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedcrypto_rsa_context * rsa = (mbedcrypto_rsa_context *) ctx;
    *olen = mbedcrypto_rsa_get_len( rsa );

    if( *olen > osize )
        return( MBEDCRYPTO_ERR_RSA_OUTPUT_TOO_LARGE );

    return( mbedcrypto_rsa_pkcs1_encrypt( rsa, f_rng, p_rng, MBEDCRYPTO_RSA_PUBLIC,
                                       ilen, input, output ) );
}

static int rsa_check_pair_wrap( const void *pub, const void *prv )
{
    return( mbedcrypto_rsa_check_pub_priv( (const mbedcrypto_rsa_context *) pub,
                                (const mbedcrypto_rsa_context *) prv ) );
}

static void *rsa_alloc_wrap( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_rsa_context ) );

    if( ctx != NULL )
        mbedcrypto_rsa_init( (mbedcrypto_rsa_context *) ctx, 0, 0 );

    return( ctx );
}

static void rsa_free_wrap( void *ctx )
{
    mbedcrypto_rsa_free( (mbedcrypto_rsa_context *) ctx );
    mbedcrypto_free( ctx );
}

static void rsa_debug( const void *ctx, mbedcrypto_pk_debug_item *items )
{
    items->type = MBEDCRYPTO_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &( ((mbedcrypto_rsa_context *) ctx)->N );

    items++;

    items->type = MBEDCRYPTO_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &( ((mbedcrypto_rsa_context *) ctx)->E );
}

const mbedcrypto_pk_info_t mbedcrypto_rsa_info = {
    MBEDCRYPTO_PK_RSA,
    "RSA",
    rsa_get_bitlen,
    rsa_can_do,
    rsa_verify_wrap,
    rsa_sign_wrap,
    rsa_decrypt_wrap,
    rsa_encrypt_wrap,
    rsa_check_pair_wrap,
    rsa_alloc_wrap,
    rsa_free_wrap,
    rsa_debug,
};
#endif /* MBEDCRYPTO_RSA_C */

#if defined(MBEDCRYPTO_ECP_C)
/*
 * Generic EC key
 */
static int eckey_can_do( mbedcrypto_pk_type_t type )
{
    return( type == MBEDCRYPTO_PK_ECKEY ||
            type == MBEDCRYPTO_PK_ECKEY_DH ||
            type == MBEDCRYPTO_PK_ECDSA );
}

static size_t eckey_get_bitlen( const void *ctx )
{
    return( ((mbedcrypto_ecp_keypair *) ctx)->grp.pbits );
}

#if defined(MBEDCRYPTO_ECDSA_C)
/* Forward declarations */
static int ecdsa_verify_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len );

static int ecdsa_sign_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

static int eckey_verify_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    mbedcrypto_ecdsa_context ecdsa;

    mbedcrypto_ecdsa_init( &ecdsa );

    if( ( ret = mbedcrypto_ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = ecdsa_verify_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len );

    mbedcrypto_ecdsa_free( &ecdsa );

    return( ret );
}

static int eckey_sign_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    mbedcrypto_ecdsa_context ecdsa;

    mbedcrypto_ecdsa_init( &ecdsa );

    if( ( ret = mbedcrypto_ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = ecdsa_sign_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len,
                               f_rng, p_rng );

    mbedcrypto_ecdsa_free( &ecdsa );

    return( ret );
}

#endif /* MBEDCRYPTO_ECDSA_C */

static int eckey_check_pair( const void *pub, const void *prv )
{
    return( mbedcrypto_ecp_check_pub_priv( (const mbedcrypto_ecp_keypair *) pub,
                                (const mbedcrypto_ecp_keypair *) prv ) );
}

static void *eckey_alloc_wrap( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_ecp_keypair ) );

    if( ctx != NULL )
        mbedcrypto_ecp_keypair_init( ctx );

    return( ctx );
}

static void eckey_free_wrap( void *ctx )
{
    mbedcrypto_ecp_keypair_free( (mbedcrypto_ecp_keypair *) ctx );
    mbedcrypto_free( ctx );
}

static void eckey_debug( const void *ctx, mbedcrypto_pk_debug_item *items )
{
    items->type = MBEDCRYPTO_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &( ((mbedcrypto_ecp_keypair *) ctx)->Q );
}

const mbedcrypto_pk_info_t mbedcrypto_eckey_info = {
    MBEDCRYPTO_PK_ECKEY,
    "EC",
    eckey_get_bitlen,
    eckey_can_do,
#if defined(MBEDCRYPTO_ECDSA_C)
    eckey_verify_wrap,
    eckey_sign_wrap,
#else
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,
    eckey_free_wrap,
    eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do( mbedcrypto_pk_type_t type )
{
    return( type == MBEDCRYPTO_PK_ECKEY ||
            type == MBEDCRYPTO_PK_ECKEY_DH );
}

const mbedcrypto_pk_info_t mbedcrypto_eckeydh_info = {
    MBEDCRYPTO_PK_ECKEY_DH,
    "EC_DH",
    eckey_get_bitlen,         /* Same underlying key structure */
    eckeydh_can_do,
    NULL,
    NULL,
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,       /* Same underlying key structure */
    eckey_free_wrap,        /* Same underlying key structure */
    eckey_debug,            /* Same underlying key structure */
};
#endif /* MBEDCRYPTO_ECP_C */

#if defined(MBEDCRYPTO_ECDSA_C)
static int ecdsa_can_do( mbedcrypto_pk_type_t type )
{
    return( type == MBEDCRYPTO_PK_ECDSA );
}

static int ecdsa_verify_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    ((void) md_alg);

    ret = mbedcrypto_ecdsa_read_signature( (mbedcrypto_ecdsa_context *) ctx,
                                hash, hash_len, sig, sig_len );

    if( ret == MBEDCRYPTO_ERR_ECP_SIG_LEN_MISMATCH )
        return( MBEDCRYPTO_ERR_PK_SIG_LEN_MISMATCH );

    return( ret );
}

static int ecdsa_sign_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( mbedcrypto_ecdsa_write_signature( (mbedcrypto_ecdsa_context *) ctx,
                md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng ) );
}

static void *ecdsa_alloc_wrap( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_ecdsa_context ) );

    if( ctx != NULL )
        mbedcrypto_ecdsa_init( (mbedcrypto_ecdsa_context *) ctx );

    return( ctx );
}

static void ecdsa_free_wrap( void *ctx )
{
    mbedcrypto_ecdsa_free( (mbedcrypto_ecdsa_context *) ctx );
    mbedcrypto_free( ctx );
}

const mbedcrypto_pk_info_t mbedcrypto_ecdsa_info = {
    MBEDCRYPTO_PK_ECDSA,
    "ECDSA",
    eckey_get_bitlen,     /* Compatible key structures */
    ecdsa_can_do,
    ecdsa_verify_wrap,
    ecdsa_sign_wrap,
    NULL,
    NULL,
    eckey_check_pair,   /* Compatible key structures */
    ecdsa_alloc_wrap,
    ecdsa_free_wrap,
    eckey_debug,        /* Compatible key structures */
};
#endif /* MBEDCRYPTO_ECDSA_C */

#if defined(MBEDCRYPTO_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int rsa_alt_can_do( mbedcrypto_pk_type_t type )
{
    return( type == MBEDCRYPTO_PK_RSA );
}

static size_t rsa_alt_get_bitlen( const void *ctx )
{
    const mbedcrypto_rsa_alt_context *rsa_alt = (const mbedcrypto_rsa_alt_context *) ctx;

    return( 8 * rsa_alt->key_len_func( rsa_alt->key ) );
}

static int rsa_alt_sign_wrap( void *ctx, mbedcrypto_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedcrypto_rsa_alt_context *rsa_alt = (mbedcrypto_rsa_alt_context *) ctx;

#if SIZE_MAX > UINT_MAX
    if( UINT_MAX < hash_len )
        return( MBEDCRYPTO_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    *sig_len = rsa_alt->key_len_func( rsa_alt->key );

    return( rsa_alt->sign_func( rsa_alt->key, f_rng, p_rng, MBEDCRYPTO_RSA_PRIVATE,
                md_alg, (unsigned int) hash_len, hash, sig ) );
}

static int rsa_alt_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedcrypto_rsa_alt_context *rsa_alt = (mbedcrypto_rsa_alt_context *) ctx;

    ((void) f_rng);
    ((void) p_rng);

    if( ilen != rsa_alt->key_len_func( rsa_alt->key ) )
        return( MBEDCRYPTO_ERR_RSA_BAD_INPUT_DATA );

    return( rsa_alt->decrypt_func( rsa_alt->key,
                MBEDCRYPTO_RSA_PRIVATE, olen, input, output, osize ) );
}

#if defined(MBEDCRYPTO_RSA_C)
static int rsa_alt_check_pair( const void *pub, const void *prv )
{
    unsigned char sig[MBEDCRYPTO_MPI_MAX_SIZE];
    unsigned char hash[32];
    size_t sig_len = 0;
    int ret;

    if( rsa_alt_get_bitlen( prv ) != rsa_get_bitlen( pub ) )
        return( MBEDCRYPTO_ERR_RSA_KEY_CHECK_FAILED );

    memset( hash, 0x2a, sizeof( hash ) );

    if( ( ret = rsa_alt_sign_wrap( (void *) prv, MBEDCRYPTO_MD_NONE,
                                   hash, sizeof( hash ),
                                   sig, &sig_len, NULL, NULL ) ) != 0 )
    {
        return( ret );
    }

    if( rsa_verify_wrap( (void *) pub, MBEDCRYPTO_MD_NONE,
                         hash, sizeof( hash ), sig, sig_len ) != 0 )
    {
        return( MBEDCRYPTO_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}
#endif /* MBEDCRYPTO_RSA_C */

static void *rsa_alt_alloc_wrap( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_rsa_alt_context ) );

    if( ctx != NULL )
        memset( ctx, 0, sizeof( mbedcrypto_rsa_alt_context ) );

    return( ctx );
}

static void rsa_alt_free_wrap( void *ctx )
{
    mbedcrypto_platform_zeroize( ctx, sizeof( mbedcrypto_rsa_alt_context ) );
    mbedcrypto_free( ctx );
}

const mbedcrypto_pk_info_t mbedcrypto_rsa_alt_info = {
    MBEDCRYPTO_PK_RSA_ALT,
    "RSA-alt",
    rsa_alt_get_bitlen,
    rsa_alt_can_do,
    NULL,
    rsa_alt_sign_wrap,
    rsa_alt_decrypt_wrap,
    NULL,
#if defined(MBEDCRYPTO_RSA_C)
    rsa_alt_check_pair,
#else
    NULL,
#endif
    rsa_alt_alloc_wrap,
    rsa_alt_free_wrap,
    NULL,
};

#endif /* MBEDCRYPTO_PK_RSA_ALT_SUPPORT */

#endif /* MBEDCRYPTO_PK_C */
