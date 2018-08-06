/**
 * \file psa/crypto_struct.h
 *
 * \brief PSA cryptography module: Mbed Crypto structured type implementations
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains the definitions of some data structures with
 * implementation-specific definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, it is expected that the front-end and the back-end
 * would have different versions of this file.
 */
/*
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

/* Include the Mbed Crypto configuration file, the way Mbed Crypto does it
 * in each of its header files. */
#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "../mbedcrypto/config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#include "mbedcrypto/cipher.h"
#include "mbedcrypto/cmac.h"
#include "mbedcrypto/gcm.h"
#include "mbedcrypto/md.h"
#include "mbedcrypto/md2.h"
#include "mbedcrypto/md4.h"
#include "mbedcrypto/md5.h"
#include "mbedcrypto/ripemd160.h"
#include "mbedcrypto/sha1.h"
#include "mbedcrypto/sha256.h"
#include "mbedcrypto/sha512.h"

struct psa_hash_operation_s
{
    psa_algorithm_t alg;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(MBEDCRYPTO_MD2_C)
        mbedcrypto_md2_context md2;
#endif
#if defined(MBEDCRYPTO_MD4_C)
        mbedcrypto_md4_context md4;
#endif
#if defined(MBEDCRYPTO_MD5_C)
        mbedcrypto_md5_context md5;
#endif
#if defined(MBEDCRYPTO_RIPEMD160_C)
        mbedcrypto_ripemd160_context ripemd160;
#endif
#if defined(MBEDCRYPTO_SHA1_C)
        mbedcrypto_sha1_context sha1;
#endif
#if defined(MBEDCRYPTO_SHA256_C)
        mbedcrypto_sha256_context sha256;
#endif
#if defined(MBEDCRYPTO_SHA512_C)
        mbedcrypto_sha512_context sha512;
#endif
    } ctx;
};


typedef struct
{
        /** The hash context. */
        struct psa_hash_operation_s hash_ctx;
        /** The HMAC part of the context. */
        uint8_t opad[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
} psa_hmac_internal_data;


struct psa_mac_operation_s
{
    psa_algorithm_t alg;
    unsigned int key_set : 1;
    unsigned int iv_required : 1;
    unsigned int iv_set : 1;
    unsigned int has_input : 1;
    unsigned int is_sign : 1;
    uint8_t mac_size;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(MBEDCRYPTO_MD_C)
        psa_hmac_internal_data hmac;
#endif
#if defined(MBEDCRYPTO_CMAC_C)
        mbedcrypto_cipher_context_t cmac;
#endif
    } ctx;
};

struct psa_cipher_operation_s
{
    psa_algorithm_t alg;
    unsigned int key_set : 1;
    unsigned int iv_required : 1;
    unsigned int iv_set : 1;
    uint8_t iv_size;
    uint8_t block_size;
    union
    {
        mbedcrypto_cipher_context_t cipher;
    } ctx;
};

typedef struct
{
    uint8_t *info;
    size_t info_length;
    psa_hmac_internal_data hmac;
    uint8_t prk[PSA_HASH_MAX_SIZE];
    uint8_t output_block[PSA_HASH_MAX_SIZE];
#if PSA_HASH_MAX_SIZE > 0xff
#error "PSA_HASH_MAX_SIZE does not fit in uint8_t"
#endif
    uint8_t offset_in_block;
    uint8_t block_number;
} psa_hkdf_generator_t;

struct psa_crypto_generator_s
{
    psa_algorithm_t alg;
    size_t capacity;
    union
    {
        struct
        {
            uint8_t *data;
            size_t size;
        } buffer;
#if defined(MBEDCRYPTO_MD_C)
        psa_hkdf_generator_t hkdf;
#endif
    } ctx;
};

#define PSA_CRYPTO_GENERATOR_INIT {0, 0, {{0, 0}}}
static inline struct psa_crypto_generator_s psa_crypto_generator_init( void )
{
    const struct psa_crypto_generator_s v = PSA_CRYPTO_GENERATOR_INIT;
    return( v );
}

struct psa_key_policy_s
{
    psa_key_usage_t usage;
    psa_algorithm_t alg;
};

#endif /* PSA_CRYPTO_STRUCT_H */
