/**
 * \file md4.h
 *
 * \brief MD4 message digest algorithm (hash function)
 *
 * \warning MD4 is considered a weak message digest and its use constitutes a
 *          security risk. We recommend considering stronger message digests
 *          instead.
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
 *
 */
#ifndef MBEDCRYPTO_MD4_H
#define MBEDCRYPTO_MD4_H

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define MBEDCRYPTO_ERR_MD4_HW_ACCEL_FAILED                   -0x002D  /**< MD4 hardware accelerator failed */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDCRYPTO_MD4_ALT)
// Regular implementation
//

/**
 * \brief          MD4 context structure
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
mbedcrypto_md4_context;

#else  /* MBEDCRYPTO_MD4_ALT */
#include "md4_alt.h"
#endif /* MBEDCRYPTO_MD4_ALT */

/**
 * \brief          Initialize MD4 context
 *
 * \param ctx      MD4 context to be initialized
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedcrypto_md4_init( mbedcrypto_md4_context *ctx );

/**
 * \brief          Clear MD4 context
 *
 * \param ctx      MD4 context to be cleared
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedcrypto_md4_free( mbedcrypto_md4_context *ctx );

/**
 * \brief          Clone (the state of) an MD4 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
void mbedcrypto_md4_clone( mbedcrypto_md4_context *dst,
                        const mbedcrypto_md4_context *src );

/**
 * \brief          MD4 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 */
int mbedcrypto_md4_starts_ret( mbedcrypto_md4_context *ctx );

/**
 * \brief          MD4 process buffer
 *
 * \param ctx      MD4 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedcrypto_md4_update_ret( mbedcrypto_md4_context *ctx,
                            const unsigned char *input,
                            size_t ilen );

/**
 * \brief          MD4 final digest
 *
 * \param ctx      MD4 context
 * \param output   MD4 checksum result
 *
 * \return         0 if successful
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedcrypto_md4_finish_ret( mbedcrypto_md4_context *ctx,
                            unsigned char output[16] );

/**
 * \brief          MD4 process data block (internal use only)
 *
 * \param ctx      MD4 context
 * \param data     buffer holding one block of data
 *
 * \return         0 if successful
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedcrypto_internal_md4_process( mbedcrypto_md4_context *ctx,
                                  const unsigned char data[64] );

#if !defined(MBEDCRYPTO_DEPRECATED_REMOVED)
#if defined(MBEDCRYPTO_DEPRECATED_WARNING)
#define MBEDCRYPTO_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDCRYPTO_DEPRECATED
#endif
/**
 * \brief          MD4 context setup
 *
 * \deprecated     Superseded by mbedcrypto_md4_starts_ret() in 2.7.0
 *
 * \param ctx      context to be initialized
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_md4_starts( mbedcrypto_md4_context *ctx );

/**
 * \brief          MD4 process buffer
 *
 * \deprecated     Superseded by mbedcrypto_md4_update_ret() in 2.7.0
 *
 * \param ctx      MD4 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_md4_update( mbedcrypto_md4_context *ctx,
                                            const unsigned char *input,
                                            size_t ilen );

/**
 * \brief          MD4 final digest
 *
 * \deprecated     Superseded by mbedcrypto_md4_finish_ret() in 2.7.0
 *
 * \param ctx      MD4 context
 * \param output   MD4 checksum result
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_md4_finish( mbedcrypto_md4_context *ctx,
                                            unsigned char output[16] );

/**
 * \brief          MD4 process data block (internal use only)
 *
 * \deprecated     Superseded by mbedcrypto_internal_md4_process() in 2.7.0
 *
 * \param ctx      MD4 context
 * \param data     buffer holding one block of data
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_md4_process( mbedcrypto_md4_context *ctx,
                                             const unsigned char data[64] );

#undef MBEDCRYPTO_DEPRECATED
#endif /* !MBEDCRYPTO_DEPRECATED_REMOVED */

/**
 * \brief          Output = MD4( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD4 checksum result
 *
 * \return         0 if successful
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedcrypto_md4_ret( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16] );

#if !defined(MBEDCRYPTO_DEPRECATED_REMOVED)
#if defined(MBEDCRYPTO_DEPRECATED_WARNING)
#define MBEDCRYPTO_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDCRYPTO_DEPRECATED
#endif
/**
 * \brief          Output = MD4( input buffer )
 *
 * \deprecated     Superseded by mbedcrypto_md4_ret() in 2.7.0
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD4 checksum result
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_md4( const unsigned char *input,
                                     size_t ilen,
                                     unsigned char output[16] );

#undef MBEDCRYPTO_DEPRECATED
#endif /* !MBEDCRYPTO_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 *
 * \warning        MD4 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
int mbedcrypto_md4_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* mbedcrypto_md4.h */
