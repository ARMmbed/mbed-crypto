/**
 * \file psa/crypto_struct.h
 *
 * \brief PSA cryptography module: Mbed TLS structured type implementations
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains the definitions of some data structures with
 * implementation-specific sizes.
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

struct psa_hash_operation_s
{
    psa_algorithm_t alg;
    uint8_t reserved[217];
};

struct psa_mac_operation_s
{
    psa_algorithm_t alg;
    uint8_t reserved[353];
};

struct psa_cipher_operation_s
{
    psa_algorithm_t alg;
    uint8_t reserved[97];
};

struct psa_crypto_generator_s
{
    psa_algorithm_t alg;
    size_t capacity;
    uint8_t reserved[497];
};

#define PSA_CRYPTO_GENERATOR_INIT {0, 0, {0}}
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
