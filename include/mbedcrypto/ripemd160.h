/**
 * \file ripemd160.h
 *
 * \brief RIPE MD-160 message digest
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
#ifndef MBEDCRYPTO_RIPEMD160_H
#define MBEDCRYPTO_RIPEMD160_H

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define MBEDCRYPTO_ERR_RIPEMD160_HW_ACCEL_FAILED             -0x0031  /**< RIPEMD160 hardware accelerator failed */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDCRYPTO_RIPEMD160_ALT)
// Regular implementation
//

/**
 * \brief          RIPEMD-160 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[5];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
mbedcrypto_ripemd160_context;

#else  /* MBEDCRYPTO_RIPEMD160_ALT */
#include "ripemd160.h"
#endif /* MBEDCRYPTO_RIPEMD160_ALT */

/**
 * \brief          Initialize RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be initialized
 */
void mbedcrypto_ripemd160_init( mbedcrypto_ripemd160_context *ctx );

/**
 * \brief          Clear RIPEMD-160 context
 *
 * \param ctx      RIPEMD-160 context to be cleared
 */
void mbedcrypto_ripemd160_free( mbedcrypto_ripemd160_context *ctx );

/**
 * \brief          Clone (the state of) an RIPEMD-160 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedcrypto_ripemd160_clone( mbedcrypto_ripemd160_context *dst,
                        const mbedcrypto_ripemd160_context *src );

/**
 * \brief          RIPEMD-160 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 */
int mbedcrypto_ripemd160_starts_ret( mbedcrypto_ripemd160_context *ctx );

/**
 * \brief          RIPEMD-160 process buffer
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 */
int mbedcrypto_ripemd160_update_ret( mbedcrypto_ripemd160_context *ctx,
                                  const unsigned char *input,
                                  size_t ilen );

/**
 * \brief          RIPEMD-160 final digest
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
int mbedcrypto_ripemd160_finish_ret( mbedcrypto_ripemd160_context *ctx,
                                  unsigned char output[20] );

/**
 * \brief          RIPEMD-160 process data block (internal use only)
 *
 * \param ctx      RIPEMD-160 context
 * \param data     buffer holding one block of data
 *
 * \return         0 if successful
 */
int mbedcrypto_internal_ripemd160_process( mbedcrypto_ripemd160_context *ctx,
                                        const unsigned char data[64] );

#if !defined(MBEDCRYPTO_DEPRECATED_REMOVED)
#if defined(MBEDCRYPTO_DEPRECATED_WARNING)
#define MBEDCRYPTO_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDCRYPTO_DEPRECATED
#endif
/**
 * \brief          RIPEMD-160 context setup
 *
 * \deprecated     Superseded by mbedcrypto_ripemd160_starts_ret() in 2.7.0
 *
 * \param ctx      context to be initialized
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_ripemd160_starts(
                                            mbedcrypto_ripemd160_context *ctx );

/**
 * \brief          RIPEMD-160 process buffer
 *
 * \deprecated     Superseded by mbedcrypto_ripemd160_update_ret() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_ripemd160_update(
                                                mbedcrypto_ripemd160_context *ctx,
                                                const unsigned char *input,
                                                size_t ilen );

/**
 * \brief          RIPEMD-160 final digest
 *
 * \deprecated     Superseded by mbedcrypto_ripemd160_finish_ret() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_ripemd160_finish(
                                                mbedcrypto_ripemd160_context *ctx,
                                                unsigned char output[20] );

/**
 * \brief          RIPEMD-160 process data block (internal use only)
 *
 * \deprecated     Superseded by mbedcrypto_internal_ripemd160_process() in 2.7.0
 *
 * \param ctx      RIPEMD-160 context
 * \param data     buffer holding one block of data
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_ripemd160_process(
                                            mbedcrypto_ripemd160_context *ctx,
                                            const unsigned char data[64] );

#undef MBEDCRYPTO_DEPRECATED
#endif /* !MBEDCRYPTO_DEPRECATED_REMOVED */

/**
 * \brief          Output = RIPEMD-160( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 *
 * \return         0 if successful
 */
int mbedcrypto_ripemd160_ret( const unsigned char *input,
                           size_t ilen,
                           unsigned char output[20] );

#if !defined(MBEDCRYPTO_DEPRECATED_REMOVED)
#if defined(MBEDCRYPTO_DEPRECATED_WARNING)
#define MBEDCRYPTO_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDCRYPTO_DEPRECATED
#endif
/**
 * \brief          Output = RIPEMD-160( input buffer )
 *
 * \deprecated     Superseded by mbedcrypto_ripemd160_ret() in 2.7.0
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   RIPEMD-160 checksum result
 */
MBEDCRYPTO_DEPRECATED void mbedcrypto_ripemd160( const unsigned char *input,
                                           size_t ilen,
                                           unsigned char output[20] );

#undef MBEDCRYPTO_DEPRECATED
#endif /* !MBEDCRYPTO_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedcrypto_ripemd160_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* mbedcrypto_ripemd160.h */
