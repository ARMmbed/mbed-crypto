/**
 * \file pem.h
 *
 * \brief Privacy Enhanced Mail (PEM) decoding
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
#ifndef MBEDCRYPTO_PEM_H
#define MBEDCRYPTO_PEM_H

#include <stddef.h>

/**
 * \name PEM Error codes
 * These error codes are returned in case of errors reading the
 * PEM data.
 * \{
 */
#define MBEDCRYPTO_ERR_PEM_NO_HEADER_FOOTER_PRESENT          -0x1080  /**< No PEM header or footer found. */
#define MBEDCRYPTO_ERR_PEM_INVALID_DATA                      -0x1100  /**< PEM string is not as expected. */
#define MBEDCRYPTO_ERR_PEM_ALLOC_FAILED                      -0x1180  /**< Failed to allocate memory. */
#define MBEDCRYPTO_ERR_PEM_INVALID_ENC_IV                    -0x1200  /**< RSA IV is not in hex-format. */
#define MBEDCRYPTO_ERR_PEM_UNKNOWN_ENC_ALG                   -0x1280  /**< Unsupported key encryption algorithm. */
#define MBEDCRYPTO_ERR_PEM_PASSWORD_REQUIRED                 -0x1300  /**< Private key password can't be empty. */
#define MBEDCRYPTO_ERR_PEM_PASSWORD_MISMATCH                 -0x1380  /**< Given private key password does not allow for correct decryption. */
#define MBEDCRYPTO_ERR_PEM_FEATURE_UNAVAILABLE               -0x1400  /**< Unavailable feature, e.g. hashing/encryption combination. */
#define MBEDCRYPTO_ERR_PEM_BAD_INPUT_DATA                    -0x1480  /**< Bad input parameters to function. */
/* \} name */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDCRYPTO_PEM_PARSE_C)
/**
 * \brief       PEM context structure
 */
typedef struct
{
    unsigned char *buf;     /*!< buffer for decoded data             */
    size_t buflen;          /*!< length of the buffer                */
    unsigned char *info;    /*!< buffer for extra header information */
}
mbedcrypto_pem_context;

/**
 * \brief       PEM context setup
 *
 * \param ctx   context to be initialized
 */
void mbedcrypto_pem_init( mbedcrypto_pem_context *ctx );

/**
 * \brief       Read a buffer for PEM information and store the resulting
 *              data into the specified context buffers.
 *
 * \param ctx       context to use
 * \param header    header string to seek and expect
 * \param footer    footer string to seek and expect
 * \param data      source data to look in (must be nul-terminated)
 * \param pwd       password for decryption (can be NULL)
 * \param pwdlen    length of password
 * \param use_len   destination for total length used (set after header is
 *                  correctly read, so unless you get
 *                  MBEDCRYPTO_ERR_PEM_BAD_INPUT_DATA or
 *                  MBEDCRYPTO_ERR_PEM_NO_HEADER_FOOTER_PRESENT, use_len is
 *                  the length to skip)
 *
 * \note            Attempts to check password correctness by verifying if
 *                  the decrypted text starts with an ASN.1 sequence of
 *                  appropriate length
 *
 * \return          0 on success, or a specific PEM error code
 */
int mbedcrypto_pem_read_buffer( mbedcrypto_pem_context *ctx, const char *header, const char *footer,
                     const unsigned char *data,
                     const unsigned char *pwd,
                     size_t pwdlen, size_t *use_len );

/**
 * \brief       PEM context memory freeing
 *
 * \param ctx   context to be freed
 */
void mbedcrypto_pem_free( mbedcrypto_pem_context *ctx );
#endif /* MBEDCRYPTO_PEM_PARSE_C */

#if defined(MBEDCRYPTO_PEM_WRITE_C)
/**
 * \brief           Write a buffer of PEM information from a DER encoded
 *                  buffer.
 *
 * \param header    header string to write
 * \param footer    footer string to write
 * \param der_data  DER data to write
 * \param der_len   length of the DER data
 * \param buf       buffer to write to
 * \param buf_len   length of output buffer
 * \param olen      total length written / required (if buf_len is not enough)
 *
 * \return          0 on success, or a specific PEM or BASE64 error code. On
 *                  MBEDCRYPTO_ERR_BASE64_BUFFER_TOO_SMALL olen is the required
 *                  size.
 */
int mbedcrypto_pem_write_buffer( const char *header, const char *footer,
                      const unsigned char *der_data, size_t der_len,
                      unsigned char *buf, size_t buf_len, size_t *olen );
#endif /* MBEDCRYPTO_PEM_WRITE_C */

#ifdef __cplusplus
}
#endif

#endif /* pem.h */
