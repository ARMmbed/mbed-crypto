/**
 * \file md_wrap.c
 *
 * \brief Generic message digest wrapper for Mbed Crypto
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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

#if defined(MBEDCRYPTO_MD_C)

#include "mbedcrypto/md_internal.h"

#if defined(MBEDCRYPTO_MD2_C)
#include "mbedcrypto/md2.h"
#endif

#if defined(MBEDCRYPTO_MD4_C)
#include "mbedcrypto/md4.h"
#endif

#if defined(MBEDCRYPTO_MD5_C)
#include "mbedcrypto/md5.h"
#endif

#if defined(MBEDCRYPTO_RIPEMD160_C)
#include "mbedcrypto/ripemd160.h"
#endif

#if defined(MBEDCRYPTO_SHA1_C)
#include "mbedcrypto/sha1.h"
#endif

#if defined(MBEDCRYPTO_SHA256_C)
#include "mbedcrypto/sha256.h"
#endif

#if defined(MBEDCRYPTO_SHA512_C)
#include "mbedcrypto/sha512.h"
#endif

#if defined(MBEDCRYPTO_PLATFORM_C)
#include "mbedcrypto/platform.h"
#else
#include <stdlib.h>
#define mbedcrypto_calloc    calloc
#define mbedcrypto_free       free
#endif

#if defined(MBEDCRYPTO_MD2_C)

static int md2_starts_wrap( void *ctx )
{
    return( mbedcrypto_md2_starts_ret( (mbedcrypto_md2_context *) ctx ) );
}

static int md2_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedcrypto_md2_update_ret( (mbedcrypto_md2_context *) ctx, input, ilen ) );
}

static int md2_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedcrypto_md2_finish_ret( (mbedcrypto_md2_context *) ctx, output ) );
}

static void *md2_ctx_alloc( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_md2_context ) );

    if( ctx != NULL )
        mbedcrypto_md2_init( (mbedcrypto_md2_context *) ctx );

    return( ctx );
}

static void md2_ctx_free( void *ctx )
{
    mbedcrypto_md2_free( (mbedcrypto_md2_context *) ctx );
    mbedcrypto_free( ctx );
}

static void md2_clone_wrap( void *dst, const void *src )
{
    mbedcrypto_md2_clone( (mbedcrypto_md2_context *) dst,
                 (const mbedcrypto_md2_context *) src );
}

static int md2_process_wrap( void *ctx, const unsigned char *data )
{
    ((void) data);

    return( mbedcrypto_internal_md2_process( (mbedcrypto_md2_context *) ctx ) );
}

const mbedcrypto_md_info_t mbedcrypto_md2_info = {
    MBEDCRYPTO_MD_MD2,
    "MD2",
    16,
    16,
    md2_starts_wrap,
    md2_update_wrap,
    md2_finish_wrap,
    mbedcrypto_md2_ret,
    md2_ctx_alloc,
    md2_ctx_free,
    md2_clone_wrap,
    md2_process_wrap,
};

#endif /* MBEDCRYPTO_MD2_C */

#if defined(MBEDCRYPTO_MD4_C)

static int md4_starts_wrap( void *ctx )
{
    return( mbedcrypto_md4_starts_ret( (mbedcrypto_md4_context *) ctx ) );
}

static int md4_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedcrypto_md4_update_ret( (mbedcrypto_md4_context *) ctx, input, ilen ) );
}

static int md4_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedcrypto_md4_finish_ret( (mbedcrypto_md4_context *) ctx, output ) );
}

static void *md4_ctx_alloc( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_md4_context ) );

    if( ctx != NULL )
        mbedcrypto_md4_init( (mbedcrypto_md4_context *) ctx );

    return( ctx );
}

static void md4_ctx_free( void *ctx )
{
    mbedcrypto_md4_free( (mbedcrypto_md4_context *) ctx );
    mbedcrypto_free( ctx );
}

static void md4_clone_wrap( void *dst, const void *src )
{
    mbedcrypto_md4_clone( (mbedcrypto_md4_context *) dst,
                       (const mbedcrypto_md4_context *) src );
}

static int md4_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedcrypto_internal_md4_process( (mbedcrypto_md4_context *) ctx, data ) );
}

const mbedcrypto_md_info_t mbedcrypto_md4_info = {
    MBEDCRYPTO_MD_MD4,
    "MD4",
    16,
    64,
    md4_starts_wrap,
    md4_update_wrap,
    md4_finish_wrap,
    mbedcrypto_md4_ret,
    md4_ctx_alloc,
    md4_ctx_free,
    md4_clone_wrap,
    md4_process_wrap,
};

#endif /* MBEDCRYPTO_MD4_C */

#if defined(MBEDCRYPTO_MD5_C)

static int md5_starts_wrap( void *ctx )
{
    return( mbedcrypto_md5_starts_ret( (mbedcrypto_md5_context *) ctx ) );
}

static int md5_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedcrypto_md5_update_ret( (mbedcrypto_md5_context *) ctx, input, ilen ) );
}

static int md5_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedcrypto_md5_finish_ret( (mbedcrypto_md5_context *) ctx, output ) );
}

static void *md5_ctx_alloc( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_md5_context ) );

    if( ctx != NULL )
        mbedcrypto_md5_init( (mbedcrypto_md5_context *) ctx );

    return( ctx );
}

static void md5_ctx_free( void *ctx )
{
    mbedcrypto_md5_free( (mbedcrypto_md5_context *) ctx );
    mbedcrypto_free( ctx );
}

static void md5_clone_wrap( void *dst, const void *src )
{
    mbedcrypto_md5_clone( (mbedcrypto_md5_context *) dst,
                       (const mbedcrypto_md5_context *) src );
}

static int md5_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedcrypto_internal_md5_process( (mbedcrypto_md5_context *) ctx, data ) );
}

const mbedcrypto_md_info_t mbedcrypto_md5_info = {
    MBEDCRYPTO_MD_MD5,
    "MD5",
    16,
    64,
    md5_starts_wrap,
    md5_update_wrap,
    md5_finish_wrap,
    mbedcrypto_md5_ret,
    md5_ctx_alloc,
    md5_ctx_free,
    md5_clone_wrap,
    md5_process_wrap,
};

#endif /* MBEDCRYPTO_MD5_C */

#if defined(MBEDCRYPTO_RIPEMD160_C)

static int ripemd160_starts_wrap( void *ctx )
{
    return( mbedcrypto_ripemd160_starts_ret( (mbedcrypto_ripemd160_context *) ctx ) );
}

static int ripemd160_update_wrap( void *ctx, const unsigned char *input,
                                   size_t ilen )
{
    return( mbedcrypto_ripemd160_update_ret( (mbedcrypto_ripemd160_context *) ctx,
                                          input, ilen ) );
}

static int ripemd160_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedcrypto_ripemd160_finish_ret( (mbedcrypto_ripemd160_context *) ctx,
                                          output ) );
}

static void *ripemd160_ctx_alloc( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_ripemd160_context ) );

    if( ctx != NULL )
        mbedcrypto_ripemd160_init( (mbedcrypto_ripemd160_context *) ctx );

    return( ctx );
}

static void ripemd160_ctx_free( void *ctx )
{
    mbedcrypto_ripemd160_free( (mbedcrypto_ripemd160_context *) ctx );
    mbedcrypto_free( ctx );
}

static void ripemd160_clone_wrap( void *dst, const void *src )
{
    mbedcrypto_ripemd160_clone( (mbedcrypto_ripemd160_context *) dst,
                       (const mbedcrypto_ripemd160_context *) src );
}

static int ripemd160_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedcrypto_internal_ripemd160_process(
                                (mbedcrypto_ripemd160_context *) ctx, data ) );
}

const mbedcrypto_md_info_t mbedcrypto_ripemd160_info = {
    MBEDCRYPTO_MD_RIPEMD160,
    "RIPEMD160",
    20,
    64,
    ripemd160_starts_wrap,
    ripemd160_update_wrap,
    ripemd160_finish_wrap,
    mbedcrypto_ripemd160_ret,
    ripemd160_ctx_alloc,
    ripemd160_ctx_free,
    ripemd160_clone_wrap,
    ripemd160_process_wrap,
};

#endif /* MBEDCRYPTO_RIPEMD160_C */

#if defined(MBEDCRYPTO_SHA1_C)

static int sha1_starts_wrap( void *ctx )
{
    return( mbedcrypto_sha1_starts_ret( (mbedcrypto_sha1_context *) ctx ) );
}

static int sha1_update_wrap( void *ctx, const unsigned char *input,
                              size_t ilen )
{
    return( mbedcrypto_sha1_update_ret( (mbedcrypto_sha1_context *) ctx,
                                     input, ilen ) );
}

static int sha1_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedcrypto_sha1_finish_ret( (mbedcrypto_sha1_context *) ctx, output ) );
}

static void *sha1_ctx_alloc( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_sha1_context ) );

    if( ctx != NULL )
        mbedcrypto_sha1_init( (mbedcrypto_sha1_context *) ctx );

    return( ctx );
}

static void sha1_clone_wrap( void *dst, const void *src )
{
    mbedcrypto_sha1_clone( (mbedcrypto_sha1_context *) dst,
                  (const mbedcrypto_sha1_context *) src );
}

static void sha1_ctx_free( void *ctx )
{
    mbedcrypto_sha1_free( (mbedcrypto_sha1_context *) ctx );
    mbedcrypto_free( ctx );
}

static int sha1_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedcrypto_internal_sha1_process( (mbedcrypto_sha1_context *) ctx,
                                           data ) );
}

const mbedcrypto_md_info_t mbedcrypto_sha1_info = {
    MBEDCRYPTO_MD_SHA1,
    "SHA1",
    20,
    64,
    sha1_starts_wrap,
    sha1_update_wrap,
    sha1_finish_wrap,
    mbedcrypto_sha1_ret,
    sha1_ctx_alloc,
    sha1_ctx_free,
    sha1_clone_wrap,
    sha1_process_wrap,
};

#endif /* MBEDCRYPTO_SHA1_C */

/*
 * Wrappers for generic message digests
 */
#if defined(MBEDCRYPTO_SHA256_C)

static int sha224_starts_wrap( void *ctx )
{
    return( mbedcrypto_sha256_starts_ret( (mbedcrypto_sha256_context *) ctx, 1 ) );
}

static int sha224_update_wrap( void *ctx, const unsigned char *input,
                                size_t ilen )
{
    return( mbedcrypto_sha256_update_ret( (mbedcrypto_sha256_context *) ctx,
                                       input, ilen ) );
}

static int sha224_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedcrypto_sha256_finish_ret( (mbedcrypto_sha256_context *) ctx,
                                       output ) );
}

static int sha224_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedcrypto_sha256_ret( input, ilen, output, 1 ) );
}

static void *sha224_ctx_alloc( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_sha256_context ) );

    if( ctx != NULL )
        mbedcrypto_sha256_init( (mbedcrypto_sha256_context *) ctx );

    return( ctx );
}

static void sha224_ctx_free( void *ctx )
{
    mbedcrypto_sha256_free( (mbedcrypto_sha256_context *) ctx );
    mbedcrypto_free( ctx );
}

static void sha224_clone_wrap( void *dst, const void *src )
{
    mbedcrypto_sha256_clone( (mbedcrypto_sha256_context *) dst,
                    (const mbedcrypto_sha256_context *) src );
}

static int sha224_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedcrypto_internal_sha256_process( (mbedcrypto_sha256_context *) ctx,
                                             data ) );
}

const mbedcrypto_md_info_t mbedcrypto_sha224_info = {
    MBEDCRYPTO_MD_SHA224,
    "SHA224",
    28,
    64,
    sha224_starts_wrap,
    sha224_update_wrap,
    sha224_finish_wrap,
    sha224_wrap,
    sha224_ctx_alloc,
    sha224_ctx_free,
    sha224_clone_wrap,
    sha224_process_wrap,
};

static int sha256_starts_wrap( void *ctx )
{
    return( mbedcrypto_sha256_starts_ret( (mbedcrypto_sha256_context *) ctx, 0 ) );
}

static int sha256_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedcrypto_sha256_ret( input, ilen, output, 0 ) );
}

const mbedcrypto_md_info_t mbedcrypto_sha256_info = {
    MBEDCRYPTO_MD_SHA256,
    "SHA256",
    32,
    64,
    sha256_starts_wrap,
    sha224_update_wrap,
    sha224_finish_wrap,
    sha256_wrap,
    sha224_ctx_alloc,
    sha224_ctx_free,
    sha224_clone_wrap,
    sha224_process_wrap,
};

#endif /* MBEDCRYPTO_SHA256_C */

#if defined(MBEDCRYPTO_SHA512_C)

static int sha384_starts_wrap( void *ctx )
{
    return( mbedcrypto_sha512_starts_ret( (mbedcrypto_sha512_context *) ctx, 1 ) );
}

static int sha384_update_wrap( void *ctx, const unsigned char *input,
                               size_t ilen )
{
    return( mbedcrypto_sha512_update_ret( (mbedcrypto_sha512_context *) ctx,
                                       input, ilen ) );
}

static int sha384_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedcrypto_sha512_finish_ret( (mbedcrypto_sha512_context *) ctx,
                                       output ) );
}

static int sha384_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedcrypto_sha512_ret( input, ilen, output, 1 ) );
}

static void *sha384_ctx_alloc( void )
{
    void *ctx = mbedcrypto_calloc( 1, sizeof( mbedcrypto_sha512_context ) );

    if( ctx != NULL )
        mbedcrypto_sha512_init( (mbedcrypto_sha512_context *) ctx );

    return( ctx );
}

static void sha384_ctx_free( void *ctx )
{
    mbedcrypto_sha512_free( (mbedcrypto_sha512_context *) ctx );
    mbedcrypto_free( ctx );
}

static void sha384_clone_wrap( void *dst, const void *src )
{
    mbedcrypto_sha512_clone( (mbedcrypto_sha512_context *) dst,
                    (const mbedcrypto_sha512_context *) src );
}

static int sha384_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedcrypto_internal_sha512_process( (mbedcrypto_sha512_context *) ctx,
                                             data ) );
}

const mbedcrypto_md_info_t mbedcrypto_sha384_info = {
    MBEDCRYPTO_MD_SHA384,
    "SHA384",
    48,
    128,
    sha384_starts_wrap,
    sha384_update_wrap,
    sha384_finish_wrap,
    sha384_wrap,
    sha384_ctx_alloc,
    sha384_ctx_free,
    sha384_clone_wrap,
    sha384_process_wrap,
};

static int sha512_starts_wrap( void *ctx )
{
    return( mbedcrypto_sha512_starts_ret( (mbedcrypto_sha512_context *) ctx, 0 ) );
}

static int sha512_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedcrypto_sha512_ret( input, ilen, output, 0 ) );
}

const mbedcrypto_md_info_t mbedcrypto_sha512_info = {
    MBEDCRYPTO_MD_SHA512,
    "SHA512",
    64,
    128,
    sha512_starts_wrap,
    sha384_update_wrap,
    sha384_finish_wrap,
    sha512_wrap,
    sha384_ctx_alloc,
    sha384_ctx_free,
    sha384_clone_wrap,
    sha384_process_wrap,
};

#endif /* MBEDCRYPTO_SHA512_C */

#endif /* MBEDCRYPTO_MD_C */
