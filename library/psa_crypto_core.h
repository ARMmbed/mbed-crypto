/*
 *  PSA crypto core internal interfaces
 */
/*  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#ifndef PSA_CRYPTO_CORE_H
#define PSA_CRYPTO_CORE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"

#include "mbedtls/ecp.h"
#include "mbedtls/rsa.h"

/** The data structure representing a key slot, containing key material
 * and metadata for one key.
 */
typedef struct
{
     psa_core_key_attributes_t attr;
    union
    {
        /* Raw-data key (key_type_is_raw_bytes() in psa_crypto.c) */
        struct raw_data
        {
            uint8_t *data;
            size_t bytes;
        } raw;
#if defined(MBEDTLS_RSA_C)
        /* RSA public key or key pair */
        mbedtls_rsa_context *rsa;
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
        /* EC public key or key pair */
        mbedtls_ecp_keypair *ecp;
#endif /* MBEDTLS_ECP_C */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
        /* Any key type in a secure element */
        struct se
        {
            psa_key_slot_number_t slot_number;
        } se;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
        void * vendor_context;
    } data;
} psa_key_slot_t;

/* A mask of key attribute flags used only internally.
 * Currently there aren't any. */
#define PSA_KA_MASK_INTERNAL_ONLY (     \
        0 )

/** Test whether a key slot is occupied.
 *
 * A key slot is occupied iff the key type is nonzero. This works because
 * no valid key can have 0 as its key type.
 *
 * \param[in] slot      The key slot to test.
 *
 * \return 1 if the slot is occupied, 0 otherwise.
 */
static inline int psa_is_key_slot_occupied( const psa_key_slot_t *slot )
{
    return( slot->attr.type != 0 );
}

/** Retrieve flags from psa_key_slot_t::attr::core::flags.
 *
 * \param[in] slot      The key slot to query.
 * \param mask          The mask of bits to extract.
 *
 * \return The key attribute flags in the given slot,
 *         bitwise-anded with \p mask.
 */
static inline uint16_t psa_key_slot_get_flags( const psa_key_slot_t *slot,
                                               uint16_t mask )
{
    return( slot->attr.flags & mask );
}

/** Set flags in psa_key_slot_t::attr::core::flags.
 *
 * \param[in,out] slot  The key slot to modify.
 * \param mask          The mask of bits to modify.
 * \param value         The new value of the selected bits.
 */
static inline void psa_key_slot_set_flags( psa_key_slot_t *slot,
                                           uint16_t mask,
                                           uint16_t value )
{
    slot->attr.flags = ( ( ~mask & slot->attr.flags ) |
                              ( mask & value ) );
}

/** Turn on flags in psa_key_slot_t::attr::core::flags.
 *
 * \param[in,out] slot  The key slot to modify.
 * \param mask          The mask of bits to set.
 */
static inline void psa_key_slot_set_bits_in_flags( psa_key_slot_t *slot,
                                                   uint16_t mask )
{
    slot->attr.flags |= mask;
}

/** Turn off flags in psa_key_slot_t::attr::core::flags.
 *
 * \param[in,out] slot  The key slot to modify.
 * \param mask          The mask of bits to clear.
 */
static inline void psa_key_slot_clear_bits( psa_key_slot_t *slot,
                                            uint16_t mask )
{
    slot->attr.flags &= ~mask;
}

/**
 * \brief Generate a vendor defined key or key pair.
 *
 * \note    This function has to be defined by the vendor.
 *          A weakly linked version is provided by default and returns
 *          PSA_ERROR_NOT_SUPPORTED. Do not use this function directly;
 *          to generate a key, use psa_generate_key() instead.
 *
 * \param[in] slot
 * \param[in] bits
 * \param[in] domain_parameters
 * \param[in] domain_parameters_size
 *
 *
 * \retval #PSA_SUCCESS
 *         Success.
 *         If the key is persistent, the key material and the key's metadata
 *         have been saved to persistent storage.
 *
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval Implementation dependent.
 */
psa_status_t psa_generate_key_vendor(psa_key_slot_t * slot,
                                     size_t           bits,
                                     const uint8_t  * domain_parameters,
                                     size_t           domain_parameters_size);

/** Completely wipe a slot in memory, including its policy.
 *
 * Persistent storage is not affected.
 *
 * \param[in,out] slot  The key slot to wipe.
 *
 * \retval PSA_SUCCESS
 *         Success. This includes the case of a key slot that was
 *         already fully wiped.
 * \retval PSA_ERROR_CORRUPTION_DETECTED
 */
psa_status_t psa_wipe_key_slot( psa_key_slot_t *slot );

/**
 * \brief Sign a hash or short message with a vendor defined private key.
 *
 * Note that to perform a hash-and-sign signature algorithm, you must
 * first calculate the hash by calling psa_hash_setup(), psa_hash_update()
 * and psa_hash_finish(). Then pass the resulting hash as the \p hash
 * parameter to this function. You can use #PSA_ALG_SIGN_GET_HASH(\p alg)
 * to determine the hash algorithm to use.
 *
 * \param slot                  Key slot to use for the operation.
 *                              It must be an asymmetric key pair.
 * \param alg                   A signature algorithm that is compatible with
 *                              the type of \p handle.
 * \param[in] hash              The hash or message to sign.
 * \param hash_length           Size of the \p hash buffer in bytes.
 * \param[out] signature        Buffer where the signature is to be written.
 * \param signature_size        Size of the \p signature buffer in bytes.
 * \param[out] signature_length On success, the number of bytes
 *                              that make up the returned signature value.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p signature buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(\c key_type, \c key_bits, \p alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \p handle.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval Implementation dependent
 */
psa_status_t psa_asymmetric_sign_vendor(psa_key_slot_t * slot,
                                        psa_algorithm_t  alg,
                                        const uint8_t  * hash,
                                        size_t           hash_length,
                                        uint8_t        * signature,
                                        size_t           signature_size,
                                        size_t         * signature_length);

/**
 * \brief Verify the signature a hash or short message using a vendor defined public key.
 *
 * Note that to perform a hash-and-sign signature algorithm, you must
 * first calculate the hash by calling psa_hash_setup(), psa_hash_update()
 * and psa_hash_finish(). Then pass the resulting hash as the \p hash
 * parameter to this function. You can use #PSA_ALG_SIGN_GET_HASH(\p alg)
 * to determine the hash algorithm to use.
 *
 * \param handle            Key slot to use for the operation.
 *                          It must be a public key or an asymmetric key pair.
 * \param alg               A signature algorithm that is compatible with
 *                          the type of \p handle.
 * \param[in] hash          The hash or message whose signature is to be
 *                          verified.
 * \param hash_length       Size of the \p hash buffer in bytes.
 * \param[in] signature     Buffer containing the signature to verify.
 * \param signature_length  Size of the \p signature buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         The signature is valid.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 * \retval Implementation dependent
 */
psa_status_t psa_asymmetric_verify_vendor(psa_key_slot_t * slot,
                                          psa_algorithm_t  alg,
                                          const uint8_t  * hash,
                                          size_t           hash_length,
                                          uint8_t        * signature,
                                          size_t           signature_length);

/** Import key data into a slot.
 *
 * `slot->type` must have been set previously.
 * This function assumes that the slot does not contain any key material yet.
 * On failure, the slot content is unchanged.
 *
 * Persistent storage is not affected.
 *
 * \param[in,out] slot  The key slot to import data into.
 *                      Its `type` field must have previously been set to
 *                      the desired key type.
 *                      It must not contain any key material yet.
 * \param[in] data      Buffer containing the key material to parse and import.
 * \param data_length   Size of \p data in bytes.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t psa_import_key_into_slot( psa_key_slot_t *slot,
                                       const uint8_t *data,
                                       size_t data_length );

#endif /* PSA_CRYPTO_CORE_H */
