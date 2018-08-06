/**
 * \file check_config.h
 *
 * \brief Consistency checks for configuration options
 */
/*
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

/*
 * It is recommended to include this file from your config.h
 * in order to catch dependency issues early.
 */

#ifndef MBEDCRYPTO_CHECK_CONFIG_H
#define MBEDCRYPTO_CHECK_CONFIG_H

/*
 * We assume CHAR_BIT is 8 in many places. In practice, this is true on our
 * target platforms, so not an issue, but let's just be extra sure.
 */
#include <limits.h>
#if CHAR_BIT != 8
#error "Mbed Crypto requires a platform with 8-bit chars"
#endif

#if defined(_WIN32)
#if !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_C is required on Windows"
#endif

/* Fix the config here. Not convenient to put an #ifdef _WIN32 in config.h as
 * it would confuse config.pl. */
#if !defined(MBEDCRYPTO_PLATFORM_SNPRINTF_ALT) && \
    !defined(MBEDCRYPTO_PLATFORM_SNPRINTF_MACRO)
#define MBEDCRYPTO_PLATFORM_SNPRINTF_ALT
#endif
#endif /* _WIN32 */

#if defined(TARGET_LIKE_MBED) && \
    ( defined(MBEDCRYPTO_NET_C) || defined(MBEDCRYPTO_TIMING_C) )
#error "The NET and TIMING modules are not available for mbed OS - please use the network and timing functions provided by mbed OS"
#endif

#if defined(MBEDCRYPTO_DEPRECATED_WARNING) && \
    !defined(__GNUC__) && !defined(__clang__)
#error "MBEDCRYPTO_DEPRECATED_WARNING only works with GCC and Clang"
#endif

#if defined(MBEDCRYPTO_HAVE_TIME_DATE) && !defined(MBEDCRYPTO_HAVE_TIME)
#error "MBEDCRYPTO_HAVE_TIME_DATE without MBEDCRYPTO_HAVE_TIME does not make sense"
#endif

#if defined(MBEDCRYPTO_AESNI_C) && !defined(MBEDCRYPTO_HAVE_ASM)
#error "MBEDCRYPTO_AESNI_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_CTR_DRBG_C) && !defined(MBEDCRYPTO_AES_C)
#error "MBEDCRYPTO_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_DHM_C) && !defined(MBEDCRYPTO_BIGNUM_C)
#error "MBEDCRYPTO_DHM_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_TRUNCATED_HMAC_COMPAT) && !defined(MBEDCRYPTO_SSL_TRUNCATED_HMAC)
#error "MBEDCRYPTO_SSL_TRUNCATED_HMAC_COMPAT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_CMAC_C) && \
    !defined(MBEDCRYPTO_AES_C) && !defined(MBEDCRYPTO_DES_C)
#error "MBEDCRYPTO_CMAC_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECDH_C) && !defined(MBEDCRYPTO_ECP_C)
#error "MBEDCRYPTO_ECDH_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECDSA_C) &&            \
    ( !defined(MBEDCRYPTO_ECP_C) ||           \
      !defined(MBEDCRYPTO_ASN1_PARSE_C) ||    \
      !defined(MBEDCRYPTO_ASN1_WRITE_C) )
#error "MBEDCRYPTO_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECJPAKE_C) &&           \
    ( !defined(MBEDCRYPTO_ECP_C) || !defined(MBEDCRYPTO_MD_C) )
#error "MBEDCRYPTO_ECJPAKE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECDSA_DETERMINISTIC) && !defined(MBEDCRYPTO_HMAC_DRBG_C)
#error "MBEDCRYPTO_ECDSA_DETERMINISTIC defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_C) && ( !defined(MBEDCRYPTO_BIGNUM_C) || (   \
    !defined(MBEDCRYPTO_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(MBEDCRYPTO_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(MBEDCRYPTO_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(MBEDCRYPTO_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(MBEDCRYPTO_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(MBEDCRYPTO_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(MBEDCRYPTO_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(MBEDCRYPTO_ECP_DP_BP512R1_ENABLED)   &&                  \
    !defined(MBEDCRYPTO_ECP_DP_SECP192K1_ENABLED) &&                  \
    !defined(MBEDCRYPTO_ECP_DP_SECP224K1_ENABLED) &&                  \
    !defined(MBEDCRYPTO_ECP_DP_SECP256K1_ENABLED) ) )
#error "MBEDCRYPTO_ECP_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ENTROPY_C) && (!defined(MBEDCRYPTO_SHA512_C) &&      \
                                    !defined(MBEDCRYPTO_SHA256_C))
#error "MBEDCRYPTO_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(MBEDCRYPTO_ENTROPY_C) && defined(MBEDCRYPTO_SHA512_C) &&         \
    defined(MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN) && (MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN > 64)
#error "MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(MBEDCRYPTO_ENTROPY_C) &&                                            \
    ( !defined(MBEDCRYPTO_SHA512_C) || defined(MBEDCRYPTO_ENTROPY_FORCE_SHA256) ) \
    && defined(MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN) && (MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN > 32)
#error "MBEDCRYPTO_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(MBEDCRYPTO_ENTROPY_C) && \
    defined(MBEDCRYPTO_ENTROPY_FORCE_SHA256) && !defined(MBEDCRYPTO_SHA256_C)
#error "MBEDCRYPTO_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_TEST_NULL_ENTROPY) && \
    ( !defined(MBEDCRYPTO_ENTROPY_C) || !defined(MBEDCRYPTO_NO_DEFAULT_ENTROPY_SOURCES) )
#error "MBEDCRYPTO_TEST_NULL_ENTROPY defined, but not all prerequisites"
#endif
#if defined(MBEDCRYPTO_TEST_NULL_ENTROPY) && \
     ( defined(MBEDCRYPTO_ENTROPY_NV_SEED) || defined(MBEDCRYPTO_ENTROPY_HARDWARE_ALT) || \
    defined(MBEDCRYPTO_HAVEGE_C) )
#error "MBEDCRYPTO_TEST_NULL_ENTROPY defined, but entropy sources too"
#endif

#if defined(MBEDCRYPTO_GCM_C) && (                                        \
        !defined(MBEDCRYPTO_AES_C) && !defined(MBEDCRYPTO_CAMELLIA_C) )
#error "MBEDCRYPTO_GCM_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_RANDOMIZE_JAC_ALT) && !defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
#error "MBEDCRYPTO_ECP_RANDOMIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_ADD_MIXED_ALT) && !defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
#error "MBEDCRYPTO_ECP_ADD_MIXED_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_DOUBLE_JAC_ALT) && !defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
#error "MBEDCRYPTO_ECP_DOUBLE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_NORMALIZE_JAC_MANY_ALT) && !defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
#error "MBEDCRYPTO_ECP_NORMALIZE_JAC_MANY_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_NORMALIZE_JAC_ALT) && !defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
#error "MBEDCRYPTO_ECP_NORMALIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_DOUBLE_ADD_MXZ_ALT) && !defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
#error "MBEDCRYPTO_ECP_DOUBLE_ADD_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_RANDOMIZE_MXZ_ALT) && !defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
#error "MBEDCRYPTO_ECP_RANDOMIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ECP_NORMALIZE_MXZ_ALT) && !defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
#error "MBEDCRYPTO_ECP_NORMALIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_HAVEGE_C) && !defined(MBEDCRYPTO_TIMING_C)
#error "MBEDCRYPTO_HAVEGE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_HMAC_DRBG_C) && !defined(MBEDCRYPTO_MD_C)
#error "MBEDCRYPTO_HMAC_DRBG_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) &&                 \
    ( !defined(MBEDCRYPTO_ECDH_C) || !defined(MBEDCRYPTO_X509_CRT_PARSE_C) )
#error "MBEDCRYPTO_KEY_EXCHANGE_ECDH_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_ECDH_RSA_ENABLED) &&                 \
    ( !defined(MBEDCRYPTO_ECDH_C) || !defined(MBEDCRYPTO_X509_CRT_PARSE_C) )
#error "MBEDCRYPTO_KEY_EXCHANGE_ECDH_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_DHE_PSK_ENABLED) && !defined(MBEDCRYPTO_DHM_C)
#error "MBEDCRYPTO_KEY_EXCHANGE_DHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_ECDHE_PSK_ENABLED) &&                     \
    !defined(MBEDCRYPTO_ECDH_C)
#error "MBEDCRYPTO_KEY_EXCHANGE_ECDHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_DHE_RSA_ENABLED) &&                   \
    ( !defined(MBEDCRYPTO_DHM_C) || !defined(MBEDCRYPTO_RSA_C) ||           \
      !defined(MBEDCRYPTO_X509_CRT_PARSE_C) || !defined(MBEDCRYPTO_PKCS1_V15) )
#error "MBEDCRYPTO_KEY_EXCHANGE_DHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_ECDHE_RSA_ENABLED) &&                 \
    ( !defined(MBEDCRYPTO_ECDH_C) || !defined(MBEDCRYPTO_RSA_C) ||          \
      !defined(MBEDCRYPTO_X509_CRT_PARSE_C) || !defined(MBEDCRYPTO_PKCS1_V15) )
#error "MBEDCRYPTO_KEY_EXCHANGE_ECDHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) &&                 \
    ( !defined(MBEDCRYPTO_ECDH_C) || !defined(MBEDCRYPTO_ECDSA_C) ||          \
      !defined(MBEDCRYPTO_X509_CRT_PARSE_C) )
#error "MBEDCRYPTO_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_RSA_PSK_ENABLED) &&                   \
    ( !defined(MBEDCRYPTO_RSA_C) || !defined(MBEDCRYPTO_X509_CRT_PARSE_C) || \
      !defined(MBEDCRYPTO_PKCS1_V15) )
#error "MBEDCRYPTO_KEY_EXCHANGE_RSA_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_RSA_ENABLED) &&                       \
    ( !defined(MBEDCRYPTO_RSA_C) || !defined(MBEDCRYPTO_X509_CRT_PARSE_C) || \
      !defined(MBEDCRYPTO_PKCS1_V15) )
#error "MBEDCRYPTO_KEY_EXCHANGE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_KEY_EXCHANGE_ECJPAKE_ENABLED) &&                    \
    ( !defined(MBEDCRYPTO_ECJPAKE_C) || !defined(MBEDCRYPTO_SHA256_C) ||      \
      !defined(MBEDCRYPTO_ECP_DP_SECP256R1_ENABLED) )
#error "MBEDCRYPTO_KEY_EXCHANGE_ECJPAKE_ENABLED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(MBEDCRYPTO_PLATFORM_C) || !defined(MBEDCRYPTO_PLATFORM_MEMORY) )
#error "MBEDCRYPTO_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PADLOCK_C) && !defined(MBEDCRYPTO_HAVE_ASM)
#error "MBEDCRYPTO_PADLOCK_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PEM_PARSE_C) && !defined(MBEDCRYPTO_BASE64_C)
#error "MBEDCRYPTO_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PEM_WRITE_C) && !defined(MBEDCRYPTO_BASE64_C)
#error "MBEDCRYPTO_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PK_C) && \
    ( !defined(MBEDCRYPTO_RSA_C) && !defined(MBEDCRYPTO_ECP_C) )
#error "MBEDCRYPTO_PK_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PK_PARSE_C) && !defined(MBEDCRYPTO_PK_C)
#error "MBEDCRYPTO_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PK_WRITE_C) && !defined(MBEDCRYPTO_PK_C)
#error "MBEDCRYPTO_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PKCS11_C) && !defined(MBEDCRYPTO_PK_C)
#error "MBEDCRYPTO_PKCS11_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_EXIT_ALT) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_EXIT_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_EXIT_MACRO) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_EXIT_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_EXIT_MACRO) &&\
    ( defined(MBEDCRYPTO_PLATFORM_STD_EXIT) ||\
        defined(MBEDCRYPTO_PLATFORM_EXIT_ALT) )
#error "MBEDCRYPTO_PLATFORM_EXIT_MACRO and MBEDCRYPTO_PLATFORM_STD_EXIT/MBEDCRYPTO_PLATFORM_EXIT_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_TIME_ALT) &&\
    ( !defined(MBEDCRYPTO_PLATFORM_C) ||\
        !defined(MBEDCRYPTO_HAVE_TIME) )
#error "MBEDCRYPTO_PLATFORM_TIME_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_TIME_MACRO) &&\
    ( !defined(MBEDCRYPTO_PLATFORM_C) ||\
        !defined(MBEDCRYPTO_HAVE_TIME) )
#error "MBEDCRYPTO_PLATFORM_TIME_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_TIME_TYPE_MACRO) &&\
    ( !defined(MBEDCRYPTO_PLATFORM_C) ||\
        !defined(MBEDCRYPTO_HAVE_TIME) )
#error "MBEDCRYPTO_PLATFORM_TIME_TYPE_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_TIME_MACRO) &&\
    ( defined(MBEDCRYPTO_PLATFORM_STD_TIME) ||\
        defined(MBEDCRYPTO_PLATFORM_TIME_ALT) )
#error "MBEDCRYPTO_PLATFORM_TIME_MACRO and MBEDCRYPTO_PLATFORM_STD_TIME/MBEDCRYPTO_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_TIME_TYPE_MACRO) &&\
    ( defined(MBEDCRYPTO_PLATFORM_STD_TIME) ||\
        defined(MBEDCRYPTO_PLATFORM_TIME_ALT) )
#error "MBEDCRYPTO_PLATFORM_TIME_TYPE_MACRO and MBEDCRYPTO_PLATFORM_STD_TIME/MBEDCRYPTO_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_FPRINTF_ALT) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_FPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_FPRINTF_MACRO) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_FPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_FPRINTF_MACRO) &&\
    ( defined(MBEDCRYPTO_PLATFORM_STD_FPRINTF) ||\
        defined(MBEDCRYPTO_PLATFORM_FPRINTF_ALT) )
#error "MBEDCRYPTO_PLATFORM_FPRINTF_MACRO and MBEDCRYPTO_PLATFORM_STD_FPRINTF/MBEDCRYPTO_PLATFORM_FPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_FREE_MACRO) &&\
    ( !defined(MBEDCRYPTO_PLATFORM_C) || !defined(MBEDCRYPTO_PLATFORM_MEMORY) )
#error "MBEDCRYPTO_PLATFORM_FREE_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_FREE_MACRO) &&\
    defined(MBEDCRYPTO_PLATFORM_STD_FREE)
#error "MBEDCRYPTO_PLATFORM_FREE_MACRO and MBEDCRYPTO_PLATFORM_STD_FREE cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_FREE_MACRO) && !defined(MBEDCRYPTO_PLATFORM_CALLOC_MACRO)
#error "MBEDCRYPTO_PLATFORM_CALLOC_MACRO must be defined if MBEDCRYPTO_PLATFORM_FREE_MACRO is"
#endif

#if defined(MBEDCRYPTO_PLATFORM_CALLOC_MACRO) &&\
    ( !defined(MBEDCRYPTO_PLATFORM_C) || !defined(MBEDCRYPTO_PLATFORM_MEMORY) )
#error "MBEDCRYPTO_PLATFORM_CALLOC_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_CALLOC_MACRO) &&\
    defined(MBEDCRYPTO_PLATFORM_STD_CALLOC)
#error "MBEDCRYPTO_PLATFORM_CALLOC_MACRO and MBEDCRYPTO_PLATFORM_STD_CALLOC cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_CALLOC_MACRO) && !defined(MBEDCRYPTO_PLATFORM_FREE_MACRO)
#error "MBEDCRYPTO_PLATFORM_FREE_MACRO must be defined if MBEDCRYPTO_PLATFORM_CALLOC_MACRO is"
#endif

#if defined(MBEDCRYPTO_PLATFORM_MEMORY) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_MEMORY defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_PRINTF_ALT) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_PRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_PRINTF_MACRO) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_PRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_PRINTF_MACRO) &&\
    ( defined(MBEDCRYPTO_PLATFORM_STD_PRINTF) ||\
        defined(MBEDCRYPTO_PLATFORM_PRINTF_ALT) )
#error "MBEDCRYPTO_PLATFORM_PRINTF_MACRO and MBEDCRYPTO_PLATFORM_STD_PRINTF/MBEDCRYPTO_PLATFORM_PRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_SNPRINTF_ALT) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_SNPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_SNPRINTF_MACRO) && !defined(MBEDCRYPTO_PLATFORM_C)
#error "MBEDCRYPTO_PLATFORM_SNPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_SNPRINTF_MACRO) &&\
    ( defined(MBEDCRYPTO_PLATFORM_STD_SNPRINTF) ||\
        defined(MBEDCRYPTO_PLATFORM_SNPRINTF_ALT) )
#error "MBEDCRYPTO_PLATFORM_SNPRINTF_MACRO and MBEDCRYPTO_PLATFORM_STD_SNPRINTF/MBEDCRYPTO_PLATFORM_SNPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_MEM_HDR) &&\
    !defined(MBEDCRYPTO_PLATFORM_NO_STD_FUNCTIONS)
#error "MBEDCRYPTO_PLATFORM_STD_MEM_HDR defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_CALLOC) && !defined(MBEDCRYPTO_PLATFORM_MEMORY)
#error "MBEDCRYPTO_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_CALLOC) && !defined(MBEDCRYPTO_PLATFORM_MEMORY)
#error "MBEDCRYPTO_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_FREE) && !defined(MBEDCRYPTO_PLATFORM_MEMORY)
#error "MBEDCRYPTO_PLATFORM_STD_FREE defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_EXIT) &&\
    !defined(MBEDCRYPTO_PLATFORM_EXIT_ALT)
#error "MBEDCRYPTO_PLATFORM_STD_EXIT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_TIME) &&\
    ( !defined(MBEDCRYPTO_PLATFORM_TIME_ALT) ||\
        !defined(MBEDCRYPTO_HAVE_TIME) )
#error "MBEDCRYPTO_PLATFORM_STD_TIME defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_FPRINTF) &&\
    !defined(MBEDCRYPTO_PLATFORM_FPRINTF_ALT)
#error "MBEDCRYPTO_PLATFORM_STD_FPRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_PRINTF) &&\
    !defined(MBEDCRYPTO_PLATFORM_PRINTF_ALT)
#error "MBEDCRYPTO_PLATFORM_STD_PRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_SNPRINTF) &&\
    !defined(MBEDCRYPTO_PLATFORM_SNPRINTF_ALT)
#error "MBEDCRYPTO_PLATFORM_STD_SNPRINTF defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_ENTROPY_NV_SEED) &&\
    ( !defined(MBEDCRYPTO_PLATFORM_C) || !defined(MBEDCRYPTO_ENTROPY_C) )
#error "MBEDCRYPTO_ENTROPY_NV_SEED defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_NV_SEED_ALT) &&\
    !defined(MBEDCRYPTO_ENTROPY_NV_SEED)
#error "MBEDCRYPTO_PLATFORM_NV_SEED_ALT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_NV_SEED_READ) &&\
    !defined(MBEDCRYPTO_PLATFORM_NV_SEED_ALT)
#error "MBEDCRYPTO_PLATFORM_STD_NV_SEED_READ defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_STD_NV_SEED_WRITE) &&\
    !defined(MBEDCRYPTO_PLATFORM_NV_SEED_ALT)
#error "MBEDCRYPTO_PLATFORM_STD_NV_SEED_WRITE defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PLATFORM_NV_SEED_READ_MACRO) &&\
    ( defined(MBEDCRYPTO_PLATFORM_STD_NV_SEED_READ) ||\
      defined(MBEDCRYPTO_PLATFORM_NV_SEED_ALT) )
#error "MBEDCRYPTO_PLATFORM_NV_SEED_READ_MACRO and MBEDCRYPTO_PLATFORM_STD_NV_SEED_READ cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PLATFORM_NV_SEED_WRITE_MACRO) &&\
    ( defined(MBEDCRYPTO_PLATFORM_STD_NV_SEED_WRITE) ||\
      defined(MBEDCRYPTO_PLATFORM_NV_SEED_ALT) )
#error "MBEDCRYPTO_PLATFORM_NV_SEED_WRITE_MACRO and MBEDCRYPTO_PLATFORM_STD_NV_SEED_WRITE cannot be defined simultaneously"
#endif

#if defined(MBEDCRYPTO_PSA_CRYPTO_C) &&            \
    !( defined(MBEDCRYPTO_CTR_DRBG_C) &&           \
       defined(MBEDCRYPTO_ENTROPY_C) )
#error "MBEDCRYPTO_PSA_CRYPTO_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_PSA_CRYPTO_SPM) && !defined(MBEDCRYPTO_PSA_CRYPTO_C)
#error "MBEDCRYPTO_PSA_CRYPTO_SPM defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_RSA_C) && ( !defined(MBEDCRYPTO_BIGNUM_C) ||         \
    !defined(MBEDCRYPTO_OID_C) )
#error "MBEDCRYPTO_RSA_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_RSA_C) && ( !defined(MBEDCRYPTO_PKCS1_V21) &&         \
    !defined(MBEDCRYPTO_PKCS1_V15) )
#error "MBEDCRYPTO_RSA_C defined, but none of the PKCS1 versions enabled"
#endif

#if defined(MBEDCRYPTO_X509_RSASSA_PSS_SUPPORT) &&                        \
    ( !defined(MBEDCRYPTO_RSA_C) || !defined(MBEDCRYPTO_PKCS1_V21) )
#error "MBEDCRYPTO_X509_RSASSA_PSS_SUPPORT defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_PROTO_SSL3) && ( !defined(MBEDCRYPTO_MD5_C) ||     \
    !defined(MBEDCRYPTO_SHA1_C) )
#error "MBEDCRYPTO_SSL_PROTO_SSL3 defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_PROTO_TLS1) && ( !defined(MBEDCRYPTO_MD5_C) ||     \
    !defined(MBEDCRYPTO_SHA1_C) )
#error "MBEDCRYPTO_SSL_PROTO_TLS1 defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_PROTO_TLS1_1) && ( !defined(MBEDCRYPTO_MD5_C) ||     \
    !defined(MBEDCRYPTO_SHA1_C) )
#error "MBEDCRYPTO_SSL_PROTO_TLS1_1 defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_PROTO_TLS1_2) && ( !defined(MBEDCRYPTO_SHA1_C) &&     \
    !defined(MBEDCRYPTO_SHA256_C) && !defined(MBEDCRYPTO_SHA512_C) )
#error "MBEDCRYPTO_SSL_PROTO_TLS1_2 defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_PROTO_DTLS)     && \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1_1)  && \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1_2)
#error "MBEDCRYPTO_SSL_PROTO_DTLS defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_CLI_C) && !defined(MBEDCRYPTO_SSL_TLS_C)
#error "MBEDCRYPTO_SSL_CLI_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_TLS_C) && ( !defined(MBEDCRYPTO_CIPHER_C) ||     \
    !defined(MBEDCRYPTO_MD_C) )
#error "MBEDCRYPTO_SSL_TLS_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_SRV_C) && !defined(MBEDCRYPTO_SSL_TLS_C)
#error "MBEDCRYPTO_SSL_SRV_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_TLS_C) && (!defined(MBEDCRYPTO_SSL_PROTO_SSL3) && \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1) && !defined(MBEDCRYPTO_SSL_PROTO_TLS1_1) && \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1_2))
#error "MBEDCRYPTO_SSL_TLS_C defined, but no protocols are active"
#endif

#if defined(MBEDCRYPTO_SSL_TLS_C) && (defined(MBEDCRYPTO_SSL_PROTO_SSL3) && \
    defined(MBEDCRYPTO_SSL_PROTO_TLS1_1) && !defined(MBEDCRYPTO_SSL_PROTO_TLS1))
#error "Illegal protocol selection"
#endif

#if defined(MBEDCRYPTO_SSL_TLS_C) && (defined(MBEDCRYPTO_SSL_PROTO_TLS1) && \
    defined(MBEDCRYPTO_SSL_PROTO_TLS1_2) && !defined(MBEDCRYPTO_SSL_PROTO_TLS1_1))
#error "Illegal protocol selection"
#endif

#if defined(MBEDCRYPTO_SSL_TLS_C) && (defined(MBEDCRYPTO_SSL_PROTO_SSL3) && \
    defined(MBEDCRYPTO_SSL_PROTO_TLS1_2) && (!defined(MBEDCRYPTO_SSL_PROTO_TLS1) || \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1_1)))
#error "Illegal protocol selection"
#endif

#if defined(MBEDCRYPTO_SSL_DTLS_HELLO_VERIFY) && !defined(MBEDCRYPTO_SSL_PROTO_DTLS)
#error "MBEDCRYPTO_SSL_DTLS_HELLO_VERIFY  defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_DTLS_CLIENT_PORT_REUSE) && \
    !defined(MBEDCRYPTO_SSL_DTLS_HELLO_VERIFY)
#error "MBEDCRYPTO_SSL_DTLS_CLIENT_PORT_REUSE  defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_DTLS_ANTI_REPLAY) &&                              \
    ( !defined(MBEDCRYPTO_SSL_TLS_C) || !defined(MBEDCRYPTO_SSL_PROTO_DTLS) )
#error "MBEDCRYPTO_SSL_DTLS_ANTI_REPLAY  defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_DTLS_BADMAC_LIMIT) &&                              \
    ( !defined(MBEDCRYPTO_SSL_TLS_C) || !defined(MBEDCRYPTO_SSL_PROTO_DTLS) )
#error "MBEDCRYPTO_SSL_DTLS_BADMAC_LIMIT  defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_ENCRYPT_THEN_MAC) &&   \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1)   &&      \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1_1) &&      \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1_2)
#error "MBEDCRYPTO_SSL_ENCRYPT_THEN_MAC defined, but not all prerequsites"
#endif

#if defined(MBEDCRYPTO_SSL_EXTENDED_MASTER_SECRET) && \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1)   &&          \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1_1) &&          \
    !defined(MBEDCRYPTO_SSL_PROTO_TLS1_2)
#error "MBEDCRYPTO_SSL_EXTENDED_MASTER_SECRET defined, but not all prerequsites"
#endif

#if defined(MBEDCRYPTO_SSL_TICKET_C) && !defined(MBEDCRYPTO_CIPHER_C)
#error "MBEDCRYPTO_SSL_TICKET_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_CBC_RECORD_SPLITTING) && \
    !defined(MBEDCRYPTO_SSL_PROTO_SSL3) && !defined(MBEDCRYPTO_SSL_PROTO_TLS1)
#error "MBEDCRYPTO_SSL_CBC_RECORD_SPLITTING defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_SSL_SERVER_NAME_INDICATION) && \
        !defined(MBEDCRYPTO_X509_CRT_PARSE_C)
#error "MBEDCRYPTO_SSL_SERVER_NAME_INDICATION defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_THREADING_PTHREAD)
#if !defined(MBEDCRYPTO_THREADING_C) || defined(MBEDCRYPTO_THREADING_IMPL)
#error "MBEDCRYPTO_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define MBEDCRYPTO_THREADING_IMPL
#endif

#if defined(MBEDCRYPTO_THREADING_ALT)
#if !defined(MBEDCRYPTO_THREADING_C) || defined(MBEDCRYPTO_THREADING_IMPL)
#error "MBEDCRYPTO_THREADING_ALT defined, but not all prerequisites"
#endif
#define MBEDCRYPTO_THREADING_IMPL
#endif

#if defined(MBEDCRYPTO_THREADING_C) && !defined(MBEDCRYPTO_THREADING_IMPL)
#error "MBEDCRYPTO_THREADING_C defined, single threading implementation required"
#endif
#undef MBEDCRYPTO_THREADING_IMPL

#if defined(MBEDCRYPTO_VERSION_FEATURES) && !defined(MBEDCRYPTO_VERSION_C)
#error "MBEDCRYPTO_VERSION_FEATURES defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_X509_USE_C) && ( !defined(MBEDCRYPTO_BIGNUM_C) ||  \
    !defined(MBEDCRYPTO_OID_C) || !defined(MBEDCRYPTO_ASN1_PARSE_C) ||      \
    !defined(MBEDCRYPTO_PK_PARSE_C) )
#error "MBEDCRYPTO_X509_USE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_X509_CREATE_C) && ( !defined(MBEDCRYPTO_BIGNUM_C) ||  \
    !defined(MBEDCRYPTO_OID_C) || !defined(MBEDCRYPTO_ASN1_WRITE_C) ||       \
    !defined(MBEDCRYPTO_PK_WRITE_C) )
#error "MBEDCRYPTO_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_X509_CRT_PARSE_C) && ( !defined(MBEDCRYPTO_X509_USE_C) )
#error "MBEDCRYPTO_X509_CRT_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_X509_CRL_PARSE_C) && ( !defined(MBEDCRYPTO_X509_USE_C) )
#error "MBEDCRYPTO_X509_CRL_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_X509_CSR_PARSE_C) && ( !defined(MBEDCRYPTO_X509_USE_C) )
#error "MBEDCRYPTO_X509_CSR_PARSE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_X509_CRT_WRITE_C) && ( !defined(MBEDCRYPTO_X509_CREATE_C) )
#error "MBEDCRYPTO_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_X509_CSR_WRITE_C) && ( !defined(MBEDCRYPTO_X509_CREATE_C) )
#error "MBEDCRYPTO_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#if defined(MBEDCRYPTO_HAVE_INT32) && defined(MBEDCRYPTO_HAVE_INT64)
#error "MBEDCRYPTO_HAVE_INT32 and MBEDCRYPTO_HAVE_INT64 cannot be defined simultaneously"
#endif /* MBEDCRYPTO_HAVE_INT32 && MBEDCRYPTO_HAVE_INT64 */

#if ( defined(MBEDCRYPTO_HAVE_INT32) || defined(MBEDCRYPTO_HAVE_INT64) ) && \
    defined(MBEDCRYPTO_HAVE_ASM)
#error "MBEDCRYPTO_HAVE_INT32/MBEDCRYPTO_HAVE_INT64 and MBEDCRYPTO_HAVE_ASM cannot be defined simultaneously"
#endif /* (MBEDCRYPTO_HAVE_INT32 || MBEDCRYPTO_HAVE_INT64) && MBEDCRYPTO_HAVE_ASM */

/*
 * Avoid warning from -pedantic. This is a convenient place for this
 * workaround since this is included by every single file before the
 * #if defined(MBEDCRYPTO_xxx_C) that results in emtpy translation units.
 */
typedef int mbedcrypto_iso_c_forbids_empty_translation_units;

#endif /* MBEDCRYPTO_CHECK_CONFIG_H */
