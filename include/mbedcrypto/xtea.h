/**
 * \file xtea.h
 *
 * \brief XTEA block cipher (32-bit)
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
#ifndef MBEDCRYPTO_XTEA_H
#define MBEDCRYPTO_XTEA_H

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define MBEDCRYPTO_XTEA_ENCRYPT     1
#define MBEDCRYPTO_XTEA_DECRYPT     0

#define MBEDCRYPTO_ERR_XTEA_INVALID_INPUT_LENGTH             -0x0028  /**< The data input has an invalid length. */
#define MBEDCRYPTO_ERR_XTEA_HW_ACCEL_FAILED                  -0x0029  /**< XTEA hardware accelerator failed. */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDCRYPTO_XTEA_ALT)
// Regular implementation
//

/**
 * \brief          XTEA context structure
 */
typedef struct
{
    uint32_t k[4];       /*!< key */
}
mbedcrypto_xtea_context;

#else  /* MBEDCRYPTO_XTEA_ALT */
#include "xtea_alt.h"
#endif /* MBEDCRYPTO_XTEA_ALT */

/**
 * \brief          Initialize XTEA context
 *
 * \param ctx      XTEA context to be initialized
 */
void mbedcrypto_xtea_init( mbedcrypto_xtea_context *ctx );

/**
 * \brief          Clear XTEA context
 *
 * \param ctx      XTEA context to be cleared
 */
void mbedcrypto_xtea_free( mbedcrypto_xtea_context *ctx );

/**
 * \brief          XTEA key schedule
 *
 * \param ctx      XTEA context to be initialized
 * \param key      the secret key
 */
void mbedcrypto_xtea_setup( mbedcrypto_xtea_context *ctx, const unsigned char key[16] );

/**
 * \brief          XTEA cipher function
 *
 * \param ctx      XTEA context
 * \param mode     MBEDCRYPTO_XTEA_ENCRYPT or MBEDCRYPTO_XTEA_DECRYPT
 * \param input    8-byte input block
 * \param output   8-byte output block
 *
 * \return         0 if successful
 */
int mbedcrypto_xtea_crypt_ecb( mbedcrypto_xtea_context *ctx,
                    int mode,
                    const unsigned char input[8],
                    unsigned char output[8] );

#if defined(MBEDCRYPTO_CIPHER_MODE_CBC)
/**
 * \brief          XTEA CBC cipher function
 *
 * \param ctx      XTEA context
 * \param mode     MBEDCRYPTO_XTEA_ENCRYPT or MBEDCRYPTO_XTEA_DECRYPT
 * \param length   the length of input, multiple of 8
 * \param iv       initialization vector for CBC mode
 * \param input    input block
 * \param output   output block
 *
 * \return         0 if successful,
 *                 MBEDCRYPTO_ERR_XTEA_INVALID_INPUT_LENGTH if the length % 8 != 0
 */
int mbedcrypto_xtea_crypt_cbc( mbedcrypto_xtea_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output);
#endif /* MBEDCRYPTO_CIPHER_MODE_CBC */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedcrypto_xtea_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* xtea.h */
