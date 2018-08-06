/*
 * ASN.1 buffer writing functionality
 *
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

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "mbedcrypto/config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#if defined(MBEDCRYPTO_ASN1_WRITE_C)

#include "mbedcrypto/asn1write.h"

#include <string.h>

#if defined(MBEDCRYPTO_PLATFORM_C)
#include "mbedcrypto/platform.h"
#else
#include <stdlib.h>
#define mbedcrypto_calloc    calloc
#define mbedcrypto_free       free
#endif

int mbedcrypto_asn1_write_len( unsigned char **p, unsigned char *start, size_t len )
{
    if( len < 0x80 )
    {
        if( *p - start < 1 )
            return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = (unsigned char) len;
        return( 1 );
    }

    if( len <= 0xFF )
    {
        if( *p - start < 2 )
            return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = (unsigned char) len;
        *--(*p) = 0x81;
        return( 2 );
    }

    if( len <= 0xFFFF )
    {
        if( *p - start < 3 )
            return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = 0x82;
        return( 3 );
    }

    if( len <= 0xFFFFFF )
    {
        if( *p - start < 4 )
            return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = ( len >> 16 ) & 0xFF;
        *--(*p) = 0x83;
        return( 4 );
    }

    if( len <= 0xFFFFFFFF )
    {
        if( *p - start < 5 )
            return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = ( len >> 16 ) & 0xFF;
        *--(*p) = ( len >> 24 ) & 0xFF;
        *--(*p) = 0x84;
        return( 5 );
    }

    return( MBEDCRYPTO_ERR_ASN1_INVALID_LENGTH );
}

int mbedcrypto_asn1_write_tag( unsigned char **p, unsigned char *start, unsigned char tag )
{
    if( *p - start < 1 )
        return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = tag;

    return( 1 );
}

int mbedcrypto_asn1_write_raw_buffer( unsigned char **p, unsigned char *start,
                           const unsigned char *buf, size_t size )
{
    size_t len = 0;

    if( *p < start || (size_t)( *p - start ) < size )
        return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

    len = size;
    (*p) -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}

#if defined(MBEDCRYPTO_BIGNUM_C)
int mbedcrypto_asn1_write_mpi( unsigned char **p, unsigned char *start, const mbedcrypto_mpi *X )
{
    int ret;
    size_t len = 0;

    // Write the MPI
    //
    len = mbedcrypto_mpi_size( X );

    if( *p < start || (size_t)( *p - start ) < len )
        return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

    (*p) -= len;
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_write_binary( X, *p, len ) );

    // DER format assumes 2s complement for numbers, so the leftmost bit
    // should be 0 for positive numbers and 1 for negative numbers.
    //
    if( X->s ==1 && **p & 0x80 )
    {
        if( *p - start < 1 )
            return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;
        len += 1;
    }

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_INTEGER ) );

    ret = (int) len;

cleanup:
    return( ret );
}
#endif /* MBEDCRYPTO_BIGNUM_C */

int mbedcrypto_asn1_write_null( unsigned char **p, unsigned char *start )
{
    int ret;
    size_t len = 0;

    // Write NULL
    //
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, 0) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_NULL ) );

    return( (int) len );
}

int mbedcrypto_asn1_write_oid( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len )
{
    int ret;
    size_t len = 0;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_raw_buffer( p, start,
                                  (const unsigned char *) oid, oid_len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len , mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len , mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_OID ) );

    return( (int) len );
}

int mbedcrypto_asn1_write_algorithm_identifier( unsigned char **p, unsigned char *start,
                                     const char *oid, size_t oid_len,
                                     size_t par_len )
{
    int ret;
    size_t len = 0;

    if( par_len == 0 )
        MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_null( p, start ) );
    else
        len += par_len;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_oid( p, start, oid, oid_len ) );

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start,
                                       MBEDCRYPTO_ASN1_CONSTRUCTED | MBEDCRYPTO_ASN1_SEQUENCE ) );

    return( (int) len );
}

int mbedcrypto_asn1_write_bool( unsigned char **p, unsigned char *start, int boolean )
{
    int ret;
    size_t len = 0;

    if( *p - start < 1 )
        return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = (boolean) ? 255 : 0;
    len++;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_BOOLEAN ) );

    return( (int) len );
}

int mbedcrypto_asn1_write_int( unsigned char **p, unsigned char *start, int val )
{
    int ret;
    size_t len = 0;

    if( *p - start < 1 )
        return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

    len += 1;
    *--(*p) = val;

    if( val > 0 && **p & 0x80 )
    {
        if( *p - start < 1 )
            return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;
        len += 1;
    }

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_INTEGER ) );

    return( (int) len );
}

int mbedcrypto_asn1_write_printable_string( unsigned char **p, unsigned char *start,
                                 const char *text, size_t text_len )
{
    int ret;
    size_t len = 0;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_raw_buffer( p, start,
                  (const unsigned char *) text, text_len ) );

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_PRINTABLE_STRING ) );

    return( (int) len );
}

int mbedcrypto_asn1_write_ia5_string( unsigned char **p, unsigned char *start,
                           const char *text, size_t text_len )
{
    int ret;
    size_t len = 0;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_raw_buffer( p, start,
                  (const unsigned char *) text, text_len ) );

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_IA5_STRING ) );

    return( (int) len );
}

int mbedcrypto_asn1_write_bitstring( unsigned char **p, unsigned char *start,
                          const unsigned char *buf, size_t bits )
{
    int ret;
    size_t len = 0, size;

    size = ( bits / 8 ) + ( ( bits % 8 ) ? 1 : 0 );

    // Calculate byte length
    //
    if( *p < start || (size_t)( *p - start ) < size + 1 )
        return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

    len = size + 1;
    (*p) -= size;
    memcpy( *p, buf, size );

    // Write unused bits
    //
    *--(*p) = (unsigned char) (size * 8 - bits);

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_BIT_STRING ) );

    return( (int) len );
}

int mbedcrypto_asn1_write_octet_string( unsigned char **p, unsigned char *start,
                             const unsigned char *buf, size_t size )
{
    int ret;
    size_t len = 0;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_raw_buffer( p, start, buf, size ) );

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_OCTET_STRING ) );

    return( (int) len );
}

mbedcrypto_asn1_named_data *mbedcrypto_asn1_store_named_data( mbedcrypto_asn1_named_data **head,
                                        const char *oid, size_t oid_len,
                                        const unsigned char *val,
                                        size_t val_len )
{
    mbedcrypto_asn1_named_data *cur;

    if( ( cur = mbedcrypto_asn1_find_named_data( *head, oid, oid_len ) ) == NULL )
    {
        // Add new entry if not present yet based on OID
        //
        cur = (mbedcrypto_asn1_named_data*)mbedcrypto_calloc( 1,
                                            sizeof(mbedcrypto_asn1_named_data) );
        if( cur == NULL )
            return( NULL );

        cur->oid.len = oid_len;
        cur->oid.p = mbedcrypto_calloc( 1, oid_len );
        if( cur->oid.p == NULL )
        {
            mbedcrypto_free( cur );
            return( NULL );
        }

        memcpy( cur->oid.p, oid, oid_len );

        cur->val.len = val_len;
        cur->val.p = mbedcrypto_calloc( 1, val_len );
        if( cur->val.p == NULL )
        {
            mbedcrypto_free( cur->oid.p );
            mbedcrypto_free( cur );
            return( NULL );
        }

        cur->next = *head;
        *head = cur;
    }
    else if( cur->val.len < val_len )
    {
        /*
         * Enlarge existing value buffer if needed
         * Preserve old data until the allocation succeeded, to leave list in
         * a consistent state in case allocation fails.
         */
        void *p = mbedcrypto_calloc( 1, val_len );
        if( p == NULL )
            return( NULL );

        mbedcrypto_free( cur->val.p );
        cur->val.p = p;
        cur->val.len = val_len;
    }

    if( val != NULL )
        memcpy( cur->val.p, val, val_len );

    return( cur );
}
#endif /* MBEDCRYPTO_ASN1_WRITE_C */
