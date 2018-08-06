/**
 * \file sha1.h
 *
 * \brief This file contains SHA-1 definitions and functions.
 *
 * The Secure Hash Algorithm 1 (SHA-1) cryptographic hash function is defined in
 * <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. We recommend considering stronger message
 *            digests instead.
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
#ifndef MBEDCRYPTO_SHA1_H
#define MBEDCRYPTO_SHA1_H

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define MBEDCRYPTO_ERR_SHA1_HW_ACCEL_FAILED                  -0x0035  /**< SHA-1 hardware accelerator failed */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDCRYPTO_SHA1_ALT)
// Regular implementation
//

/**
 * \brief          The SHA-1 context structure.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 */
typedef struct
{
    uint32_t total[2];          /*!< The number of Bytes processed.  */
    uint32_t state[5];          /*!< The intermediate digest state.  */
    unsigned char buffer[64];   /*!< The data block being processed. */
}
mbedcrypto_sha1_context;

#else  /* MBEDCRYPTO_SHA1_ALT */
#include "sha1_alt.h"
#endif /* MBEDCRYPTO_SHA1_ALT */

/**
 * \brief          This function initializes a SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to initialize.
 *
 */
void mbedcrypto_sha1_init( mbedcrypto_sha1_context *ctx );

/**
 * \brief          This function clears a SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to clear.
 *
 */
void mbedcrypto_sha1_free( mbedcrypto_sha1_context *ctx );

/**
 * \brief          This function clones the state of a SHA-1 context.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param dst      The SHA-1 context to clone to.
 * \param src      The SHA-1 context to clone from.
 *
 */
void mbedcrypto_sha1_clone( mbedcrypto_sha1_context *dst,
                         const mbedcrypto_sha1_context *src );

/**
 * \brief          This function starts a SHA-1 checksum calculation.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context to initialize.
 *
 * \return         \c 0 on success.
 *
 */
int mbedcrypto_sha1_starts_ret( mbedcrypto_sha1_context *ctx );

/**
 * \brief          This function feeds an input buffer into an ongoing SHA-1
 *                 checksum calculation.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 *
 * \return         \c 0 on success.
 */
int mbedcrypto_sha1_update_ret( mbedcrypto_sha1_context *ctx,
                             const unsigned char *input,
                             size_t ilen );

/**
 * \brief          This function finishes the SHA-1 operation, and writes
 *                 the result to the output buffer.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context.
 * \param output   The SHA-1 checksum result.
 *
 * \return         \c 0 on success.
 */
int mbedcrypto_sha1_finish_ret( mbedcrypto_sha1_context *ctx,
                             unsigned char output[20] );

/**
 * \brief          SHA-1 process data block (internal use only).
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param ctx      The SHA-1 context.
 * \param data     The data block being processed.
 *
 * \return         \c 0 on success.
 *
 */
int mbedcrypto_internal_sha1_process( mbedcrypto_sha1_context *ctx,
                                   const unsigned char data[64] );

#if !defined(MBEDCRYPTO_DEPRECATED_REMOVED)
#if defined(MBEDCRYPTO_DEPRECATED_WARNING)
#define MBEDCRYPTO_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDCRYPTO_DEPRECATED
#endif
/**
 * \brief          This function starts a SHA-1 checksum calculation.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \deprecated     Superseded by mbedcrypto_sha1_starts_ret() in 2.7.0.
 *
 * \param ctx      The SHA-1 context to initialize.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_sha1_starts( mbedcrypto_sha1_context *ctx );

/**
 * \brief          This function feeds an input buffer into an ongoing SHA-1
 *                 checksum calculation.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \deprecated     Superseded by mbedcrypto_sha1_update_ret() in 2.7.0.
 *
 * \param ctx      The SHA-1 context.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_sha1_update( mbedcrypto_sha1_context *ctx,
                                             const unsigned char *input,
                                             size_t ilen );

/**
 * \brief          This function finishes the SHA-1 operation, and writes
 *                 the result to the output buffer.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \deprecated     Superseded by mbedcrypto_sha1_finish_ret() in 2.7.0.
 *
 * \param ctx      The SHA-1 context.
 * \param output   The SHA-1 checksum result.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_sha1_finish( mbedcrypto_sha1_context *ctx,
                                             unsigned char output[20] );

/**
 * \brief          SHA-1 process data block (internal use only).
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \deprecated     Superseded by mbedcrypto_internal_sha1_process() in 2.7.0.
 *
 * \param ctx      The SHA-1 context.
 * \param data     The data block being processed.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_sha1_process( mbedcrypto_sha1_context *ctx,
                                              const unsigned char data[64] );

#undef MBEDCRYPTO_DEPRECATED
#endif /* !MBEDCRYPTO_DEPRECATED_REMOVED */

/**
 * \brief          This function calculates the SHA-1 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-1 result is calculated as
 *                 output = SHA-1(input buffer).
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The SHA-1 checksum result.
 *
 * \return         \c 0 on success.
 *
 */
int mbedcrypto_sha1_ret( const unsigned char *input,
                      size_t ilen,
                      unsigned char output[20] );

#if !defined(MBEDCRYPTO_DEPRECATED_REMOVED)
#if defined(MBEDCRYPTO_DEPRECATED_WARNING)
#define MBEDCRYPTO_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDCRYPTO_DEPRECATED
#endif
/**
 * \brief          This function calculates the SHA-1 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-1 result is calculated as
 *                 output = SHA-1(input buffer).
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \deprecated     Superseded by mbedcrypto_sha1_ret() in 2.7.0
 *
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The SHA-1 checksum result.
 *
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_sha1( const unsigned char *input,
                                      size_t ilen,
                                      unsigned char output[20] );

#undef MBEDCRYPTO_DEPRECATED
#endif /* !MBEDCRYPTO_DEPRECATED_REMOVED */

/**
 * \brief          The SHA-1 checkup routine.
 *
 * \warning        SHA-1 is considered a weak message digest and its use
 *                 constitutes a security risk. We recommend considering
 *                 stronger message digests instead.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 *
 */
int mbedcrypto_sha1_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* mbedcrypto_sha1.h */
