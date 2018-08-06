/**
 * \file ctr_drbg.h
 *
 * \brief    This file contains CTR_DRBG definitions and functions.
 *
 * CTR_DRBG is a standardized way of building a PRNG from a block-cipher
 * in counter mode operation, as defined in <em>NIST SP 800-90A:
 * Recommendation for Random Number Generation Using Deterministic Random
 * Bit Generators</em>.
 *
 * The Mbed Crypto implementation of CTR_DRBG uses AES-256 as the underlying
 * block cipher.
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

#ifndef MBEDCRYPTO_CTR_DRBG_H
#define MBEDCRYPTO_CTR_DRBG_H

#include "aes.h"

#if defined(MBEDCRYPTO_THREADING_C)
#include "mbedcrypto/threading.h"
#endif

#define MBEDCRYPTO_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED        -0x0034  /**< The entropy source failed. */
#define MBEDCRYPTO_ERR_CTR_DRBG_REQUEST_TOO_BIG              -0x0036  /**< The requested random buffer length is too big. */
#define MBEDCRYPTO_ERR_CTR_DRBG_INPUT_TOO_BIG                -0x0038  /**< The input (entropy + additional data) is too large. */
#define MBEDCRYPTO_ERR_CTR_DRBG_FILE_IO_ERROR                -0x003A  /**< Read or write error in file. */

#define MBEDCRYPTO_CTR_DRBG_BLOCKSIZE          16 /**< The block size used by the cipher. */
#define MBEDCRYPTO_CTR_DRBG_KEYSIZE            32 /**< The key size used by the cipher. */
#define MBEDCRYPTO_CTR_DRBG_KEYBITS            ( MBEDCRYPTO_CTR_DRBG_KEYSIZE * 8 ) /**< The key size for the DRBG operation, in bits. */
#define MBEDCRYPTO_CTR_DRBG_SEEDLEN            ( MBEDCRYPTO_CTR_DRBG_KEYSIZE + MBEDCRYPTO_CTR_DRBG_BLOCKSIZE ) /**< The seed length, calculated as (counter + AES key). */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them using the compiler command
 * line.
 * \{
 */

#if !defined(MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN)
#if defined(MBEDCRYPTO_SHA512_C) && !defined(MBEDCRYPTO_ENTROPY_FORCE_SHA256)
#define MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN        48
/**< The amount of entropy used per seed by default:
 * <ul><li>48 with SHA-512.</li>
 * <li>32 with SHA-256.</li></ul>
 */
#else
#define MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN        32
/**< Amount of entropy used per seed by default:
 * <ul><li>48 with SHA-512.</li>
 * <li>32 with SHA-256.</li></ul>
 */
#endif
#endif

#if !defined(MBEDCRYPTO_CTR_DRBG_RESEED_INTERVAL)
#define MBEDCRYPTO_CTR_DRBG_RESEED_INTERVAL    10000
/**< The interval before reseed is performed by default. */
#endif

#if !defined(MBEDCRYPTO_CTR_DRBG_MAX_INPUT)
#define MBEDCRYPTO_CTR_DRBG_MAX_INPUT          256
/**< The maximum number of additional input Bytes. */
#endif

#if !defined(MBEDCRYPTO_CTR_DRBG_MAX_REQUEST)
#define MBEDCRYPTO_CTR_DRBG_MAX_REQUEST        1024
/**< The maximum number of requested Bytes per call. */
#endif

#if !defined(MBEDCRYPTO_CTR_DRBG_MAX_SEED_INPUT)
#define MBEDCRYPTO_CTR_DRBG_MAX_SEED_INPUT     384
/**< The maximum size of seed or reseed buffer. */
#endif

/* \} name SECTION: Module settings */

#define MBEDCRYPTO_CTR_DRBG_PR_OFF             0
/**< Prediction resistance is disabled. */
#define MBEDCRYPTO_CTR_DRBG_PR_ON              1
/**< Prediction resistance is enabled. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          The CTR_DRBG context structure.
 */
typedef struct
{
    unsigned char counter[16];  /*!< The counter (V). */
    int reseed_counter;         /*!< The reseed counter. */
    int prediction_resistance;  /*!< This determines whether prediction
                                     resistance is enabled, that is
                                     whether to systematically reseed before
                                     each random generation. */
    size_t entropy_len;         /*!< The amount of entropy grabbed on each
                                     seed or reseed operation. */
    int reseed_interval;        /*!< The reseed interval. */

    mbedcrypto_aes_context aes_ctx;        /*!< The AES context. */

    /*
     * Callbacks (Entropy)
     */
    int (*f_entropy)(void *, unsigned char *, size_t);
                                /*!< The entropy callback function. */

    void *p_entropy;            /*!< The context for the entropy function. */

#if defined(MBEDCRYPTO_THREADING_C)
    mbedcrypto_threading_mutex_t mutex;
#endif
}
mbedcrypto_ctr_drbg_context;

/**
 * \brief               This function initializes the CTR_DRBG context,
 *                      and prepares it for mbedcrypto_ctr_drbg_seed()
 *                      or mbedcrypto_ctr_drbg_free().
 *
 * \param ctx           The CTR_DRBG context to initialize.
 */
void mbedcrypto_ctr_drbg_init( mbedcrypto_ctr_drbg_context *ctx );

/**
 * \brief               This function seeds and sets up the CTR_DRBG
 *                      entropy source for future reseeds.
 *
 * \note Personalization data can be provided in addition to the more generic
 *       entropy source, to make this instantiation as unique as possible.
 *
 * \param ctx           The CTR_DRBG context to seed.
 * \param f_entropy     The entropy callback, taking as arguments the
 *                      \p p_entropy context, the buffer to fill, and the
                        length of the buffer.
 * \param p_entropy     The entropy context.
 * \param custom        Personalization data, that is device-specific
                        identifiers. Can be NULL.
 * \param len           The length of the personalization data.
 *
 * \return              \c 0 on success.
 * \return              #MBEDCRYPTO_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED on failure.
 */
int mbedcrypto_ctr_drbg_seed( mbedcrypto_ctr_drbg_context *ctx,
                   int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy,
                   const unsigned char *custom,
                   size_t len );

/**
 * \brief               This function clears CTR_CRBG context data.
 *
 * \param ctx           The CTR_DRBG context to clear.
 */
void mbedcrypto_ctr_drbg_free( mbedcrypto_ctr_drbg_context *ctx );

/**
 * \brief               This function turns prediction resistance on or off.
 *                      The default value is off.
 *
 * \note                If enabled, entropy is gathered at the beginning of
 *                      every call to mbedcrypto_ctr_drbg_random_with_add().
 *                      Only use this if your entropy source has sufficient
 *                      throughput.
 *
 * \param ctx           The CTR_DRBG context.
 * \param resistance    #MBEDCRYPTO_CTR_DRBG_PR_ON or #MBEDCRYPTO_CTR_DRBG_PR_OFF.
 */
void mbedcrypto_ctr_drbg_set_prediction_resistance( mbedcrypto_ctr_drbg_context *ctx,
                                         int resistance );

/**
 * \brief               This function sets the amount of entropy grabbed on each
 *                      seed or reseed. The default value is
 *                      #MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN.
 *
 * \param ctx           The CTR_DRBG context.
 * \param len           The amount of entropy to grab.
 */
void mbedcrypto_ctr_drbg_set_entropy_len( mbedcrypto_ctr_drbg_context *ctx,
                               size_t len );

/**
 * \brief               This function sets the reseed interval.
 *                      The default value is #MBEDCRYPTO_CTR_DRBG_RESEED_INTERVAL.
 *
 * \param ctx           The CTR_DRBG context.
 * \param interval      The reseed interval.
 */
void mbedcrypto_ctr_drbg_set_reseed_interval( mbedcrypto_ctr_drbg_context *ctx,
                                   int interval );

/**
 * \brief               This function reseeds the CTR_DRBG context, that is
 *                      extracts data from the entropy source.
 *
 * \param ctx           The CTR_DRBG context.
 * \param additional    Additional data to add to the state. Can be NULL.
 * \param len           The length of the additional data.
 *
 * \return              \c 0 on success.
 * \return              #MBEDCRYPTO_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED on failure.
 */
int mbedcrypto_ctr_drbg_reseed( mbedcrypto_ctr_drbg_context *ctx,
                     const unsigned char *additional, size_t len );

/**
 * \brief              This function updates the state of the CTR_DRBG context.
 *
 * \note               If \p add_len is greater than
 *                     #MBEDCRYPTO_CTR_DRBG_MAX_SEED_INPUT, only the first
 *                     #MBEDCRYPTO_CTR_DRBG_MAX_SEED_INPUT Bytes are used.
 *                     The remaining Bytes are silently discarded.
 *
 * \param ctx          The CTR_DRBG context.
 * \param additional   The data to update the state with.
 * \param add_len      Length of \p additional data.
 *
 */
void mbedcrypto_ctr_drbg_update( mbedcrypto_ctr_drbg_context *ctx,
                      const unsigned char *additional, size_t add_len );

/**
 * \brief   This function updates a CTR_DRBG instance with additional
 *          data and uses it to generate random data.
 *
 * \note    The function automatically reseeds if the reseed counter is exceeded.
 *
 * \param p_rng         The CTR_DRBG context. This must be a pointer to a
 *                      #mbedcrypto_ctr_drbg_context structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer.
 * \param additional    Additional data to update. Can be NULL.
 * \param add_len       The length of the additional data.
 *
 * \return    \c 0 on success.
 * \return    #MBEDCRYPTO_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED or
 *            #MBEDCRYPTO_ERR_CTR_DRBG_REQUEST_TOO_BIG on failure.
 */
int mbedcrypto_ctr_drbg_random_with_add( void *p_rng,
                              unsigned char *output, size_t output_len,
                              const unsigned char *additional, size_t add_len );

/**
 * \brief   This function uses CTR_DRBG to generate random data.
 *
 * \note    The function automatically reseeds if the reseed counter is exceeded.
 *
 * \param p_rng         The CTR_DRBG context. This must be a pointer to a
 *                      #mbedcrypto_ctr_drbg_context structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer.
 *
 * \return              \c 0 on success.
 * \return              #MBEDCRYPTO_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED or
 *                      #MBEDCRYPTO_ERR_CTR_DRBG_REQUEST_TOO_BIG on failure.
 */
int mbedcrypto_ctr_drbg_random( void *p_rng,
                     unsigned char *output, size_t output_len );

#if defined(MBEDCRYPTO_FS_IO)
/**
 * \brief               This function writes a seed file.
 *
 * \param ctx           The CTR_DRBG context.
 * \param path          The name of the file.
 *
 * \return              \c 0 on success.
 * \return              #MBEDCRYPTO_ERR_CTR_DRBG_FILE_IO_ERROR on file error.
 * \return              #MBEDCRYPTO_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED on
 *                      failure.
 */
int mbedcrypto_ctr_drbg_write_seed_file( mbedcrypto_ctr_drbg_context *ctx, const char *path );

/**
 * \brief               This function reads and updates a seed file. The seed
 *                      is added to this instance.
 *
 * \param ctx           The CTR_DRBG context.
 * \param path          The name of the file.
 *
 * \return              \c 0 on success.
 * \return              #MBEDCRYPTO_ERR_CTR_DRBG_FILE_IO_ERROR on file error.
 * \return              #MBEDCRYPTO_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED or
 *                      #MBEDCRYPTO_ERR_CTR_DRBG_INPUT_TOO_BIG on failure.
 */
int mbedcrypto_ctr_drbg_update_seed_file( mbedcrypto_ctr_drbg_context *ctx, const char *path );
#endif /* MBEDCRYPTO_FS_IO */

/**
 * \brief               The CTR_DRBG checkup routine.
 *
 * \return              \c 0 on success.
 * \return              \c 1 on failure.
 */
int mbedcrypto_ctr_drbg_self_test( int verbose );

/* Internal functions (do not call directly) */
int mbedcrypto_ctr_drbg_seed_entropy_len( mbedcrypto_ctr_drbg_context *,
                               int (*)(void *, unsigned char *, size_t), void *,
                               const unsigned char *, size_t, size_t );

#ifdef __cplusplus
}
#endif

#endif /* ctr_drbg.h */
