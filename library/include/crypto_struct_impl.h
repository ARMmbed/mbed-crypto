/**
 * \file crypto_struct_impl.h
 *
 * \brief Mbed Crypto structured type implementations
 *
 * This file contains the definitions of some data structures with
 * implementation-specific definitions.
 *
 * The definitions in this file provide the implementation-specific detail of
 * the structs defined in psa/crypto_struct.h for use by the library itself
 * (not users of the library). The implementation-specific detail here is free
 * to change between versions of the library, so long as the size of the
 * structs never decreases (unless an ABI break is tolerable). The size of the
 * structs in psa/crypto_struct.h must be at least as big as those in this file
 * in order for users of the library to be able to allocate sufficient memory
 * for these structs.
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MC_CRYPTO_STRUCT_IMPL_H
#define MC_CRYPTO_STRUCT_IMPL_H

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "utils.h"

#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/md2.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

typedef struct psa_hash_operation_impl_s
{
    psa_algorithm_t alg;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(MBEDTLS_MD2_C)
        mbedtls_md2_context md2;
#endif
#if defined(MBEDTLS_MD4_C)
        mbedtls_md4_context md4;
#endif
#if defined(MBEDTLS_MD5_C)
        mbedtls_md5_context md5;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        mbedtls_ripemd160_context ripemd160;
#endif
#if defined(MBEDTLS_SHA1_C)
        mbedtls_sha1_context sha1;
#endif
#if defined(MBEDTLS_SHA256_C)
        mbedtls_sha256_context sha256;
#endif
#if defined(MBEDTLS_SHA512_C)
        mbedtls_sha512_context sha512;
#endif
    } ctx;
} psa_hash_operation_impl_t;

STATIC_ASSERT(
    sizeof(psa_hash_operation_t) >= sizeof(psa_hash_operation_impl_t),
    psa_hash_operation_t_too_small);

#if defined(MBEDTLS_MD_C)
typedef struct
{
        /** The hash context. */
        struct psa_hash_operation_s hash_ctx;
        /** The HMAC part of the context. */
        uint8_t opad[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
} psa_hmac_internal_data;
#endif /* MBEDTLS_MD_C */

typedef struct psa_mac_operation_impl_s
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
#if defined(MBEDTLS_MD_C)
        psa_hmac_internal_data hmac;
#endif
#if defined(MBEDTLS_CMAC_C)
        mbedtls_cipher_context_t cmac;
#endif
    } ctx;
} psa_mac_operation_impl_t;

STATIC_ASSERT(
    sizeof(psa_mac_operation_t) >= sizeof(psa_mac_operation_impl_t),
    psa_mac_operation_t_too_small);

typedef struct psa_cipher_operation_impl_s
{
    psa_algorithm_t alg;
    unsigned int key_set : 1;
    unsigned int iv_required : 1;
    unsigned int iv_set : 1;
    uint8_t iv_size;
    uint8_t block_size;
    union
    {
        mbedtls_cipher_context_t cipher;
    } ctx;
} psa_cipher_operation_impl_t;

STATIC_ASSERT(
    sizeof(psa_cipher_operation_t) >= sizeof(psa_cipher_operation_impl_t),
    psa_cipher_operation_t_too_small);

#if defined(MBEDTLS_MD_C)
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
#endif /* MBEDTLS_MD_C */

#if defined(MBEDTLS_MD_C)
typedef struct psa_tls12_prf_generator_s
{
    /* The TLS 1.2 PRF uses the key for each HMAC iteration,
     * hence we must store it for the lifetime of the generator.
     * This is different from HKDF, where the key is only used
     * in the extraction phase, but not during expansion. */
    unsigned char *key;
    size_t key_len;

    /* `A(i) + seed` in the notation of RFC 5246, Sect. 5 */
    uint8_t *Ai_with_seed;
    size_t Ai_with_seed_len;

    /* `HMAC_hash( prk, A(i) + seed )` in the notation of RFC 5246, Sect. 5. */
    uint8_t output_block[PSA_HASH_MAX_SIZE];

#if PSA_HASH_MAX_SIZE > 0xff
#error "PSA_HASH_MAX_SIZE does not fit in uint8_t"
#endif

    /* Indicates how many bytes in the current HMAC block have
     * already been read by the user. */
    uint8_t offset_in_block;

    /* The 1-based number of the block. */
    uint8_t block_number;

} psa_tls12_prf_generator_t;
#endif /* MBEDTLS_MD_C */

typedef struct psa_crypto_generator_impl_s
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
#if defined(MBEDTLS_MD_C)
        psa_hkdf_generator_t hkdf;
        psa_tls12_prf_generator_t tls12_prf;
#endif
    } ctx;
} psa_crypto_generator_impl_t;

STATIC_ASSERT(
    sizeof(psa_crypto_generator_t) >= sizeof(psa_crypto_generator_impl_t),
    psa_crypto_generator_t_too_small);

#endif /* MC_CRYPTO_STRUCT_IMPL_H */
