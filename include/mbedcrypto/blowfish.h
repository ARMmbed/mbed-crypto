/**
 * \file blowfish.h
 *
 * \brief Blowfish block cipher
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
#ifndef MBEDCRYPTO_BLOWFISH_H
#define MBEDCRYPTO_BLOWFISH_H

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define MBEDCRYPTO_BLOWFISH_ENCRYPT     1
#define MBEDCRYPTO_BLOWFISH_DECRYPT     0
#define MBEDCRYPTO_BLOWFISH_MAX_KEY_BITS     448
#define MBEDCRYPTO_BLOWFISH_MIN_KEY_BITS     32
#define MBEDCRYPTO_BLOWFISH_ROUNDS      16         /**< Rounds to use. When increasing this value, make sure to extend the initialisation vectors */
#define MBEDCRYPTO_BLOWFISH_BLOCKSIZE   8          /* Blowfish uses 64 bit blocks */

#define MBEDCRYPTO_ERR_BLOWFISH_INVALID_KEY_LENGTH                -0x0016  /**< Invalid key length. */
#define MBEDCRYPTO_ERR_BLOWFISH_HW_ACCEL_FAILED                   -0x0017  /**< Blowfish hardware accelerator failed. */
#define MBEDCRYPTO_ERR_BLOWFISH_INVALID_INPUT_LENGTH              -0x0018  /**< Invalid data input length. */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDCRYPTO_BLOWFISH_ALT)
// Regular implementation
//

/**
 * \brief          Blowfish context structure
 */
typedef struct
{
    uint32_t P[MBEDCRYPTO_BLOWFISH_ROUNDS + 2];    /*!<  Blowfish round keys    */
    uint32_t S[4][256];                 /*!<  key dependent S-boxes  */
}
mbedcrypto_blowfish_context;

#else  /* MBEDCRYPTO_BLOWFISH_ALT */
#include "blowfish_alt.h"
#endif /* MBEDCRYPTO_BLOWFISH_ALT */

/**
 * \brief          Initialize Blowfish context
 *
 * \param ctx      Blowfish context to be initialized
 */
void mbedcrypto_blowfish_init( mbedcrypto_blowfish_context *ctx );

/**
 * \brief          Clear Blowfish context
 *
 * \param ctx      Blowfish context to be cleared
 */
void mbedcrypto_blowfish_free( mbedcrypto_blowfish_context *ctx );

/**
 * \brief          Blowfish key schedule
 *
 * \param ctx      Blowfish context to be initialized
 * \param key      encryption key
 * \param keybits  must be between 32 and 448 bits
 *
 * \return         0 if successful, or MBEDCRYPTO_ERR_BLOWFISH_INVALID_KEY_LENGTH
 */
int mbedcrypto_blowfish_setkey( mbedcrypto_blowfish_context *ctx, const unsigned char *key,
                     unsigned int keybits );

/**
 * \brief          Blowfish-ECB block encryption/decryption
 *
 * \param ctx      Blowfish context
 * \param mode     MBEDCRYPTO_BLOWFISH_ENCRYPT or MBEDCRYPTO_BLOWFISH_DECRYPT
 * \param input    8-byte input block
 * \param output   8-byte output block
 *
 * \return         0 if successful
 */
int mbedcrypto_blowfish_crypt_ecb( mbedcrypto_blowfish_context *ctx,
                        int mode,
                        const unsigned char input[MBEDCRYPTO_BLOWFISH_BLOCKSIZE],
                        unsigned char output[MBEDCRYPTO_BLOWFISH_BLOCKSIZE] );

#if defined(MBEDCRYPTO_CIPHER_MODE_CBC)
/**
 * \brief          Blowfish-CBC buffer encryption/decryption
 *                 Length should be a multiple of the block
 *                 size (8 bytes)
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      Blowfish context
 * \param mode     MBEDCRYPTO_BLOWFISH_ENCRYPT or MBEDCRYPTO_BLOWFISH_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or
 *                 MBEDCRYPTO_ERR_BLOWFISH_INVALID_INPUT_LENGTH
 */
int mbedcrypto_blowfish_crypt_cbc( mbedcrypto_blowfish_context *ctx,
                        int mode,
                        size_t length,
                        unsigned char iv[MBEDCRYPTO_BLOWFISH_BLOCKSIZE],
                        const unsigned char *input,
                        unsigned char *output );
#endif /* MBEDCRYPTO_CIPHER_MODE_CBC */

#if defined(MBEDCRYPTO_CIPHER_MODE_CFB)
/**
 * \brief          Blowfish CFB buffer encryption/decryption.
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      Blowfish context
 * \param mode     MBEDCRYPTO_BLOWFISH_ENCRYPT or MBEDCRYPTO_BLOWFISH_DECRYPT
 * \param length   length of the input data
 * \param iv_off   offset in IV (updated after use)
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful
 */
int mbedcrypto_blowfish_crypt_cfb64( mbedcrypto_blowfish_context *ctx,
                          int mode,
                          size_t length,
                          size_t *iv_off,
                          unsigned char iv[MBEDCRYPTO_BLOWFISH_BLOCKSIZE],
                          const unsigned char *input,
                          unsigned char *output );
#endif /*MBEDCRYPTO_CIPHER_MODE_CFB */

#if defined(MBEDCRYPTO_CIPHER_MODE_CTR)
/**
 * \brief               Blowfish-CTR buffer encryption/decryption
 *
 * Warning: You have to keep the maximum use of your counter in mind!
 *
 * \param ctx           Blowfish context
 * \param length        The length of the data
 * \param nc_off        The offset in the current stream_block (for resuming
 *                      within current cipher stream). The offset pointer to
 *                      should be 0 at the start of a stream.
 * \param nonce_counter The 64-bit nonce and counter.
 * \param stream_block  The saved stream-block for resuming. Is overwritten
 *                      by the function.
 * \param input         The input data stream
 * \param output        The output data stream
 *
 * \return         0 if successful
 */
int mbedcrypto_blowfish_crypt_ctr( mbedcrypto_blowfish_context *ctx,
                        size_t length,
                        size_t *nc_off,
                        unsigned char nonce_counter[MBEDCRYPTO_BLOWFISH_BLOCKSIZE],
                        unsigned char stream_block[MBEDCRYPTO_BLOWFISH_BLOCKSIZE],
                        const unsigned char *input,
                        unsigned char *output );
#endif /* MBEDCRYPTO_CIPHER_MODE_CTR */

#ifdef __cplusplus
}
#endif

#endif /* blowfish.h */
