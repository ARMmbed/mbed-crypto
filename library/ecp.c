/*
 *  Elliptic curves over GF(p): generic functions
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

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * GECC = Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 * FIPS 186-3 http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
 * RFC 4492 for the related TLS structures and constants
 * RFC 7748 for the Curve448 and Curve25519 curve definitions
 *
 * [Curve25519] http://cr.yp.to/ecdh/curve25519-20060209.pdf
 *
 * [2] CORON, Jean-S'ebastien. Resistance against differential power analysis
 *     for elliptic curve cryptosystems. In : Cryptographic Hardware and
 *     Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 *     <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 *
 * [3] HEDABOU, Mustapha, PINEL, Pierre, et B'EN'ETEAU, Lucien. A comb method to
 *     render ECC resistant against Side Channel Attacks. IACR Cryptology
 *     ePrint Archive, 2004, vol. 2004, p. 342.
 *     <http://eprint.iacr.org/2004/342.pdf>
 */

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "mbedcrypto/config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#if defined(MBEDCRYPTO_ECP_C)

#include "mbedcrypto/ecp.h"
#include "mbedcrypto/threading.h"
#include "mbedcrypto/platform_util.h"

#include <string.h>

#if !defined(MBEDCRYPTO_ECP_ALT)

#if defined(MBEDCRYPTO_PLATFORM_C)
#include "mbedcrypto/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedcrypto_printf     printf
#define mbedcrypto_calloc    calloc
#define mbedcrypto_free       free
#endif

#include "mbedcrypto/ecp_internal.h"

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#if defined(MBEDCRYPTO_SELF_TEST)
/*
 * Counts of point addition and doubling, and field multiplications.
 * Used to test resistance of point multiplication to simple timing attacks.
 */
static unsigned long add_count, dbl_count, mul_count;
#endif

#if defined(MBEDCRYPTO_ECP_DP_SECP192R1_ENABLED) ||   \
    defined(MBEDCRYPTO_ECP_DP_SECP224R1_ENABLED) ||   \
    defined(MBEDCRYPTO_ECP_DP_SECP256R1_ENABLED) ||   \
    defined(MBEDCRYPTO_ECP_DP_SECP384R1_ENABLED) ||   \
    defined(MBEDCRYPTO_ECP_DP_SECP521R1_ENABLED) ||   \
    defined(MBEDCRYPTO_ECP_DP_BP256R1_ENABLED)   ||   \
    defined(MBEDCRYPTO_ECP_DP_BP384R1_ENABLED)   ||   \
    defined(MBEDCRYPTO_ECP_DP_BP512R1_ENABLED)   ||   \
    defined(MBEDCRYPTO_ECP_DP_SECP192K1_ENABLED) ||   \
    defined(MBEDCRYPTO_ECP_DP_SECP224K1_ENABLED) ||   \
    defined(MBEDCRYPTO_ECP_DP_SECP256K1_ENABLED)
#define ECP_SHORTWEIERSTRASS
#endif

#if defined(MBEDCRYPTO_ECP_DP_CURVE25519_ENABLED) || \
    defined(MBEDCRYPTO_ECP_DP_CURVE448_ENABLED)
#define ECP_MONTGOMERY
#endif

/*
 * Curve types: internal for now, might be exposed later
 */
typedef enum
{
    ECP_TYPE_NONE = 0,
    ECP_TYPE_SHORT_WEIERSTRASS,    /* y^2 = x^3 + a x + b      */
    ECP_TYPE_MONTGOMERY,           /* y^2 = x^3 + a x^2 + x    */
} ecp_curve_type;

/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2)
 *  - size in bits
 *  - readable name
 *
 * Curves are listed in order: largest curves first, and for a given size,
 * fastest curves first. This provides the default order for the SSL module.
 *
 * Reminder: update profiles in x509_crt.c when adding a new curves!
 */
static const mbedcrypto_ecp_curve_info ecp_supported_curves[] =
{
#if defined(MBEDCRYPTO_ECP_DP_SECP521R1_ENABLED)
    { MBEDCRYPTO_ECP_DP_SECP521R1,    25,     521,    "secp521r1"         },
#endif
#if defined(MBEDCRYPTO_ECP_DP_BP512R1_ENABLED)
    { MBEDCRYPTO_ECP_DP_BP512R1,      28,     512,    "brainpoolP512r1"   },
#endif
#if defined(MBEDCRYPTO_ECP_DP_SECP384R1_ENABLED)
    { MBEDCRYPTO_ECP_DP_SECP384R1,    24,     384,    "secp384r1"         },
#endif
#if defined(MBEDCRYPTO_ECP_DP_BP384R1_ENABLED)
    { MBEDCRYPTO_ECP_DP_BP384R1,      27,     384,    "brainpoolP384r1"   },
#endif
#if defined(MBEDCRYPTO_ECP_DP_SECP256R1_ENABLED)
    { MBEDCRYPTO_ECP_DP_SECP256R1,    23,     256,    "secp256r1"         },
#endif
#if defined(MBEDCRYPTO_ECP_DP_SECP256K1_ENABLED)
    { MBEDCRYPTO_ECP_DP_SECP256K1,    22,     256,    "secp256k1"         },
#endif
#if defined(MBEDCRYPTO_ECP_DP_BP256R1_ENABLED)
    { MBEDCRYPTO_ECP_DP_BP256R1,      26,     256,    "brainpoolP256r1"   },
#endif
#if defined(MBEDCRYPTO_ECP_DP_SECP224R1_ENABLED)
    { MBEDCRYPTO_ECP_DP_SECP224R1,    21,     224,    "secp224r1"         },
#endif
#if defined(MBEDCRYPTO_ECP_DP_SECP224K1_ENABLED)
    { MBEDCRYPTO_ECP_DP_SECP224K1,    20,     224,    "secp224k1"         },
#endif
#if defined(MBEDCRYPTO_ECP_DP_SECP192R1_ENABLED)
    { MBEDCRYPTO_ECP_DP_SECP192R1,    19,     192,    "secp192r1"         },
#endif
#if defined(MBEDCRYPTO_ECP_DP_SECP192K1_ENABLED)
    { MBEDCRYPTO_ECP_DP_SECP192K1,    18,     192,    "secp192k1"         },
#endif
    { MBEDCRYPTO_ECP_DP_NONE,          0,     0,      NULL                },
};

#define ECP_NB_CURVES   sizeof( ecp_supported_curves ) /    \
                        sizeof( ecp_supported_curves[0] )

static mbedcrypto_ecp_group_id ecp_supported_grp_id[ECP_NB_CURVES];

/*
 * List of supported curves and associated info
 */
const mbedcrypto_ecp_curve_info *mbedcrypto_ecp_curve_list( void )
{
    return( ecp_supported_curves );
}

/*
 * List of supported curves, group ID only
 */
const mbedcrypto_ecp_group_id *mbedcrypto_ecp_grp_id_list( void )
{
    static int init_done = 0;

    if( ! init_done )
    {
        size_t i = 0;
        const mbedcrypto_ecp_curve_info *curve_info;

        for( curve_info = mbedcrypto_ecp_curve_list();
             curve_info->grp_id != MBEDCRYPTO_ECP_DP_NONE;
             curve_info++ )
        {
            ecp_supported_grp_id[i++] = curve_info->grp_id;
        }
        ecp_supported_grp_id[i] = MBEDCRYPTO_ECP_DP_NONE;

        init_done = 1;
    }

    return( ecp_supported_grp_id );
}

/*
 * Get the curve info for the internal identifier
 */
const mbedcrypto_ecp_curve_info *mbedcrypto_ecp_curve_info_from_grp_id( mbedcrypto_ecp_group_id grp_id )
{
    const mbedcrypto_ecp_curve_info *curve_info;

    for( curve_info = mbedcrypto_ecp_curve_list();
         curve_info->grp_id != MBEDCRYPTO_ECP_DP_NONE;
         curve_info++ )
    {
        if( curve_info->grp_id == grp_id )
            return( curve_info );
    }

    return( NULL );
}

/*
 * Get the curve info from the TLS identifier
 */
const mbedcrypto_ecp_curve_info *mbedcrypto_ecp_curve_info_from_tls_id( uint16_t tls_id )
{
    const mbedcrypto_ecp_curve_info *curve_info;

    for( curve_info = mbedcrypto_ecp_curve_list();
         curve_info->grp_id != MBEDCRYPTO_ECP_DP_NONE;
         curve_info++ )
    {
        if( curve_info->tls_id == tls_id )
            return( curve_info );
    }

    return( NULL );
}

/*
 * Get the curve info from the name
 */
const mbedcrypto_ecp_curve_info *mbedcrypto_ecp_curve_info_from_name( const char *name )
{
    const mbedcrypto_ecp_curve_info *curve_info;

    for( curve_info = mbedcrypto_ecp_curve_list();
         curve_info->grp_id != MBEDCRYPTO_ECP_DP_NONE;
         curve_info++ )
    {
        if( strcmp( curve_info->name, name ) == 0 )
            return( curve_info );
    }

    return( NULL );
}

/*
 * Get the type of a curve
 */
static inline ecp_curve_type ecp_get_type( const mbedcrypto_ecp_group *grp )
{
    if( grp->G.X.p == NULL )
        return( ECP_TYPE_NONE );

    if( grp->G.Y.p == NULL )
        return( ECP_TYPE_MONTGOMERY );
    else
        return( ECP_TYPE_SHORT_WEIERSTRASS );
}

/*
 * Initialize (the components of) a point
 */
void mbedcrypto_ecp_point_init( mbedcrypto_ecp_point *pt )
{
    if( pt == NULL )
        return;

    mbedcrypto_mpi_init( &pt->X );
    mbedcrypto_mpi_init( &pt->Y );
    mbedcrypto_mpi_init( &pt->Z );
}

/*
 * Initialize (the components of) a group
 */
void mbedcrypto_ecp_group_init( mbedcrypto_ecp_group *grp )
{
    if( grp == NULL )
        return;

    memset( grp, 0, sizeof( mbedcrypto_ecp_group ) );
}

/*
 * Initialize (the components of) a key pair
 */
void mbedcrypto_ecp_keypair_init( mbedcrypto_ecp_keypair *key )
{
    if( key == NULL )
        return;

    mbedcrypto_ecp_group_init( &key->grp );
    mbedcrypto_mpi_init( &key->d );
    mbedcrypto_ecp_point_init( &key->Q );
}

/*
 * Unallocate (the components of) a point
 */
void mbedcrypto_ecp_point_free( mbedcrypto_ecp_point *pt )
{
    if( pt == NULL )
        return;

    mbedcrypto_mpi_free( &( pt->X ) );
    mbedcrypto_mpi_free( &( pt->Y ) );
    mbedcrypto_mpi_free( &( pt->Z ) );
}

/*
 * Unallocate (the components of) a group
 */
void mbedcrypto_ecp_group_free( mbedcrypto_ecp_group *grp )
{
    size_t i;

    if( grp == NULL )
        return;

    if( grp->h != 1 )
    {
        mbedcrypto_mpi_free( &grp->P );
        mbedcrypto_mpi_free( &grp->A );
        mbedcrypto_mpi_free( &grp->B );
        mbedcrypto_ecp_point_free( &grp->G );
        mbedcrypto_mpi_free( &grp->N );
    }

    if( grp->T != NULL )
    {
        for( i = 0; i < grp->T_size; i++ )
            mbedcrypto_ecp_point_free( &grp->T[i] );
        mbedcrypto_free( grp->T );
    }

    mbedcrypto_platform_zeroize( grp, sizeof( mbedcrypto_ecp_group ) );
}

/*
 * Unallocate (the components of) a key pair
 */
void mbedcrypto_ecp_keypair_free( mbedcrypto_ecp_keypair *key )
{
    if( key == NULL )
        return;

    mbedcrypto_ecp_group_free( &key->grp );
    mbedcrypto_mpi_free( &key->d );
    mbedcrypto_ecp_point_free( &key->Q );
}

/*
 * Copy the contents of a point
 */
int mbedcrypto_ecp_copy( mbedcrypto_ecp_point *P, const mbedcrypto_ecp_point *Q )
{
    int ret;

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &P->X, &Q->X ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &P->Y, &Q->Y ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &P->Z, &Q->Z ) );

cleanup:
    return( ret );
}

/*
 * Copy the contents of a group object
 */
int mbedcrypto_ecp_group_copy( mbedcrypto_ecp_group *dst, const mbedcrypto_ecp_group *src )
{
    return mbedcrypto_ecp_group_load( dst, src->id );
}

/*
 * Set point to zero
 */
int mbedcrypto_ecp_set_zero( mbedcrypto_ecp_point *pt )
{
    int ret;

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &pt->X , 1 ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &pt->Y , 1 ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &pt->Z , 0 ) );

cleanup:
    return( ret );
}

/*
 * Tell if a point is zero
 */
int mbedcrypto_ecp_is_zero( mbedcrypto_ecp_point *pt )
{
    return( mbedcrypto_mpi_cmp_int( &pt->Z, 0 ) == 0 );
}

/*
 * Compare two points lazyly
 */
int mbedcrypto_ecp_point_cmp( const mbedcrypto_ecp_point *P,
                           const mbedcrypto_ecp_point *Q )
{
    if( mbedcrypto_mpi_cmp_mpi( &P->X, &Q->X ) == 0 &&
        mbedcrypto_mpi_cmp_mpi( &P->Y, &Q->Y ) == 0 &&
        mbedcrypto_mpi_cmp_mpi( &P->Z, &Q->Z ) == 0 )
    {
        return( 0 );
    }

    return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );
}

/*
 * Import a non-zero point from ASCII strings
 */
int mbedcrypto_ecp_point_read_string( mbedcrypto_ecp_point *P, int radix,
                           const char *x, const char *y )
{
    int ret;

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_string( &P->X, radix, x ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_string( &P->Y, radix, y ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &P->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3)
 */
int mbedcrypto_ecp_point_write_binary( const mbedcrypto_ecp_group *grp, const mbedcrypto_ecp_point *P,
                            int format, size_t *olen,
                            unsigned char *buf, size_t buflen )
{
    int ret = 0;
    size_t plen;

    if( format != MBEDCRYPTO_ECP_PF_UNCOMPRESSED &&
        format != MBEDCRYPTO_ECP_PF_COMPRESSED )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Common case: P == 0
     */
    if( mbedcrypto_mpi_cmp_int( &P->Z, 0 ) == 0 )
    {
        if( buflen < 1 )
            return( MBEDCRYPTO_ERR_ECP_BUFFER_TOO_SMALL );

        buf[0] = 0x00;
        *olen = 1;

        return( 0 );
    }

    plen = mbedcrypto_mpi_size( &grp->P );

    if( format == MBEDCRYPTO_ECP_PF_UNCOMPRESSED )
    {
        *olen = 2 * plen + 1;

        if( buflen < *olen )
            return( MBEDCRYPTO_ERR_ECP_BUFFER_TOO_SMALL );

        buf[0] = 0x04;
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_write_binary( &P->X, buf + 1, plen ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_write_binary( &P->Y, buf + 1 + plen, plen ) );
    }
    else if( format == MBEDCRYPTO_ECP_PF_COMPRESSED )
    {
        *olen = plen + 1;

        if( buflen < *olen )
            return( MBEDCRYPTO_ERR_ECP_BUFFER_TOO_SMALL );

        buf[0] = 0x02 + mbedcrypto_mpi_get_bit( &P->Y, 0 );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_write_binary( &P->X, buf + 1, plen ) );
    }

cleanup:
    return( ret );
}

/*
 * Import a point from unsigned binary data (SEC1 2.3.4)
 */
int mbedcrypto_ecp_point_read_binary( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *pt,
                           const unsigned char *buf, size_t ilen )
{
    int ret;
    size_t plen;

    if( ilen < 1 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    if( buf[0] == 0x00 )
    {
        if( ilen == 1 )
            return( mbedcrypto_ecp_set_zero( pt ) );
        else
            return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );
    }

    plen = mbedcrypto_mpi_size( &grp->P );

    if( buf[0] != 0x04 )
        return( MBEDCRYPTO_ERR_ECP_FEATURE_UNAVAILABLE );

    if( ilen != 2 * plen + 1 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_binary( &pt->X, buf + 1, plen ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_binary( &pt->Y, buf + 1 + plen, plen ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &pt->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Import a point from a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int mbedcrypto_ecp_tls_read_point( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *pt,
                        const unsigned char **buf, size_t buf_len )
{
    unsigned char data_len;
    const unsigned char *buf_start;

    /*
     * We must have at least two bytes (1 for length, at least one for data)
     */
    if( buf_len < 2 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    data_len = *(*buf)++;
    if( data_len < 1 || data_len > buf_len - 1 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Save buffer start for read_binary and update buf
     */
    buf_start = *buf;
    *buf += data_len;

    return mbedcrypto_ecp_point_read_binary( grp, pt, buf_start, data_len );
}

/*
 * Export a point as a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int mbedcrypto_ecp_tls_write_point( const mbedcrypto_ecp_group *grp, const mbedcrypto_ecp_point *pt,
                         int format, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    int ret;

    /*
     * buffer length must be at least one, for our length byte
     */
    if( blen < 1 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedcrypto_ecp_point_write_binary( grp, pt, format,
                    olen, buf + 1, blen - 1) ) != 0 )
        return( ret );

    /*
     * write length to the first byte and update total length
     */
    buf[0] = (unsigned char) *olen;
    ++*olen;

    return( 0 );
}

/*
 * Set a group from an ECParameters record (RFC 4492)
 */
int mbedcrypto_ecp_tls_read_group( mbedcrypto_ecp_group *grp, const unsigned char **buf, size_t len )
{
    uint16_t tls_id;
    const mbedcrypto_ecp_curve_info *curve_info;

    /*
     * We expect at least three bytes (see below)
     */
    if( len < 3 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    /*
     * First byte is curve_type; only named_curve is handled
     */
    if( *(*buf)++ != MBEDCRYPTO_ECP_TLS_NAMED_CURVE )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Next two bytes are the namedcurve value
     */
    tls_id = *(*buf)++;
    tls_id <<= 8;
    tls_id |= *(*buf)++;

    if( ( curve_info = mbedcrypto_ecp_curve_info_from_tls_id( tls_id ) ) == NULL )
        return( MBEDCRYPTO_ERR_ECP_FEATURE_UNAVAILABLE );

    return mbedcrypto_ecp_group_load( grp, curve_info->grp_id );
}

/*
 * Write the ECParameters record corresponding to a group (RFC 4492)
 */
int mbedcrypto_ecp_tls_write_group( const mbedcrypto_ecp_group *grp, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    const mbedcrypto_ecp_curve_info *curve_info;

    if( ( curve_info = mbedcrypto_ecp_curve_info_from_grp_id( grp->id ) ) == NULL )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    /*
     * We are going to write 3 bytes (see below)
     */
    *olen = 3;
    if( blen < *olen )
        return( MBEDCRYPTO_ERR_ECP_BUFFER_TOO_SMALL );

    /*
     * First byte is curve_type, always named_curve
     */
    *buf++ = MBEDCRYPTO_ECP_TLS_NAMED_CURVE;

    /*
     * Next two bytes are the namedcurve value
     */
    buf[0] = curve_info->tls_id >> 8;
    buf[1] = curve_info->tls_id & 0xFF;

    return( 0 );
}

/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedcrypto_mpi_mod_mpi.
 * See the documentation of struct mbedcrypto_ecp_group.
 *
 * This function is in the critial loop for mbedcrypto_ecp_mul, so pay attention to perf.
 */
static int ecp_modp( mbedcrypto_mpi *N, const mbedcrypto_ecp_group *grp )
{
    int ret;

    if( grp->modp == NULL )
        return( mbedcrypto_mpi_mod_mpi( N, N, &grp->P ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if( ( N->s < 0 && mbedcrypto_mpi_cmp_int( N, 0 ) != 0 ) ||
        mbedcrypto_mpi_bitlen( N ) > 2 * grp->pbits )
    {
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );
    }

    MBEDCRYPTO_MPI_CHK( grp->modp( N ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while( N->s < 0 && mbedcrypto_mpi_cmp_int( N, 0 ) != 0 )
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( N, N, &grp->P ) );

    while( mbedcrypto_mpi_cmp_mpi( N, &grp->P ) >= 0 )
        /* we known P, N and the result are positive */
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_abs( N, N, &grp->P ) );

cleanup:
    return( ret );
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * mbedcrypto_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a mbedcrypto_mpi mod p in-place, general case, to use after mbedcrypto_mpi_mul_mpi
 */
#if defined(MBEDCRYPTO_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

#define MOD_MUL( N )    do { MBEDCRYPTO_MPI_CHK( ecp_modp( &N, grp ) ); INC_MUL_COUNT } \
                        while( 0 )

/*
 * Reduce a mbedcrypto_mpi mod p in-place, to use after mbedcrypto_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB( N )                                \
    while( N.s < 0 && mbedcrypto_mpi_cmp_int( &N, 0 ) != 0 )   \
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &N, &N, &grp->P ) )

/*
 * Reduce a mbedcrypto_mpi mod p in-place, to use after mbedcrypto_mpi_add_mpi and mbedcrypto_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD( N )                                \
    while( mbedcrypto_mpi_cmp_mpi( &N, &grp->P ) >= 0 )        \
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_abs( &N, &N, &grp->P ) )

#if defined(ECP_SHORTWEIERSTRASS)
/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, hence timing attacks.
 */

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */
static int ecp_normalize_jac( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *pt )
{
    int ret;
    mbedcrypto_mpi Zi, ZZi;

    if( mbedcrypto_mpi_cmp_int( &pt->Z, 0 ) == 0 )
        return( 0 );

#if defined(MBEDCRYPTO_ECP_NORMALIZE_JAC_ALT)
    if ( mbedcrypto_internal_ecp_grp_capable( grp ) )
    {
        return mbedcrypto_internal_ecp_normalize_jac( grp, pt );
    }
#endif /* MBEDCRYPTO_ECP_NORMALIZE_JAC_ALT */
    mbedcrypto_mpi_init( &Zi ); mbedcrypto_mpi_init( &ZZi );

    /*
     * X = X / Z^2  mod p
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_inv_mod( &Zi,      &pt->Z,     &grp->P ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &ZZi,     &Zi,        &Zi     ) ); MOD_MUL( ZZi );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &pt->X,   &pt->X,     &ZZi    ) ); MOD_MUL( pt->X );

    /*
     * Y = Y / Z^3  mod p
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &pt->Y,   &pt->Y,     &ZZi    ) ); MOD_MUL( pt->Y );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &pt->Y,   &pt->Y,     &Zi     ) ); MOD_MUL( pt->Y );

    /*
     * Z = 1
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &pt->Z, 1 ) );

cleanup:

    mbedcrypto_mpi_free( &Zi ); mbedcrypto_mpi_free( &ZZi );

    return( ret );
}

/*
 * Normalize jacobian coordinates of an array of (pointers to) points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul_comb().
 *
 * Cost: 1N(t) := 1I + (6t - 3)M + 1S
 */
static int ecp_normalize_jac_many( const mbedcrypto_ecp_group *grp,
                                   mbedcrypto_ecp_point *T[], size_t t_len )
{
    int ret;
    size_t i;
    mbedcrypto_mpi *c, u, Zi, ZZi;

    if( t_len < 2 )
        return( ecp_normalize_jac( grp, *T ) );

#if defined(MBEDCRYPTO_ECP_NORMALIZE_JAC_MANY_ALT)
    if ( mbedcrypto_internal_ecp_grp_capable( grp ) )
    {
        return mbedcrypto_internal_ecp_normalize_jac_many(grp, T, t_len);
    }
#endif

    if( ( c = mbedcrypto_calloc( t_len, sizeof( mbedcrypto_mpi ) ) ) == NULL )
        return( MBEDCRYPTO_ERR_ECP_ALLOC_FAILED );

    mbedcrypto_mpi_init( &u ); mbedcrypto_mpi_init( &Zi ); mbedcrypto_mpi_init( &ZZi );

    /*
     * c[i] = Z_0 * ... * Z_i
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &c[0], &T[0]->Z ) );
    for( i = 1; i < t_len; i++ )
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &c[i], &c[i-1], &T[i]->Z ) );
        MOD_MUL( c[i] );
    }

    /*
     * u = 1 / (Z_0 * ... * Z_n) mod P
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_inv_mod( &u, &c[t_len-1], &grp->P ) );

    for( i = t_len - 1; ; i-- )
    {
        /*
         * Zi = 1 / Z_i mod p
         * u = 1 / (Z_0 * ... * Z_i) mod P
         */
        if( i == 0 ) {
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &Zi, &u ) );
        }
        else
        {
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &Zi, &u, &c[i-1]  ) ); MOD_MUL( Zi );
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &u,  &u, &T[i]->Z ) ); MOD_MUL( u );
        }

        /*
         * proceed as in normalize()
         */
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &ZZi,     &Zi,      &Zi  ) ); MOD_MUL( ZZi );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T[i]->X, &T[i]->X, &ZZi ) ); MOD_MUL( T[i]->X );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T[i]->Y, &T[i]->Y, &ZZi ) ); MOD_MUL( T[i]->Y );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T[i]->Y, &T[i]->Y, &Zi  ) ); MOD_MUL( T[i]->Y );

        /*
         * Post-precessing: reclaim some memory by shrinking coordinates
         * - not storing Z (always 1)
         * - shrinking other coordinates, but still keeping the same number of
         *   limbs as P, as otherwise it will too likely be regrown too fast.
         */
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shrink( &T[i]->X, grp->P.n ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shrink( &T[i]->Y, grp->P.n ) );
        mbedcrypto_mpi_free( &T[i]->Z );

        if( i == 0 )
            break;
    }

cleanup:

    mbedcrypto_mpi_free( &u ); mbedcrypto_mpi_free( &Zi ); mbedcrypto_mpi_free( &ZZi );
    for( i = 0; i < t_len; i++ )
        mbedcrypto_mpi_free( &c[i] );
    mbedcrypto_free( c );

    return( ret );
}

/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static int ecp_safe_invert_jac( const mbedcrypto_ecp_group *grp,
                            mbedcrypto_ecp_point *Q,
                            unsigned char inv )
{
    int ret;
    unsigned char nonzero;
    mbedcrypto_mpi mQY;

    mbedcrypto_mpi_init( &mQY );

    /* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &mQY, &grp->P, &Q->Y ) );
    nonzero = mbedcrypto_mpi_cmp_int( &Q->Y, 0 ) != 0;
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_safe_cond_assign( &Q->Y, &mQY, inv & nonzero ) );

cleanup:
    mbedcrypto_mpi_free( &mQY );

    return( ret );
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2 .
 *
 * We follow the variable naming fairly closely. The formula variations that trade a MUL for a SQR
 * (plus a few ADDs) aren't useful as our bignum implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
 *
 * Cost: 1D := 3M + 4S          (A ==  0)
 *             4M + 4S          (A == -3)
 *             3M + 6S + 1a     otherwise
 */
static int ecp_double_jac( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *R,
                           const mbedcrypto_ecp_point *P )
{
    int ret;
    mbedcrypto_mpi M, S, T, U;

#if defined(MBEDCRYPTO_SELF_TEST)
    dbl_count++;
#endif

#if defined(MBEDCRYPTO_ECP_DOUBLE_JAC_ALT)
    if ( mbedcrypto_internal_ecp_grp_capable( grp ) )
    {
        return mbedcrypto_internal_ecp_double_jac( grp, R, P );
    }
#endif /* MBEDCRYPTO_ECP_DOUBLE_JAC_ALT */

    mbedcrypto_mpi_init( &M ); mbedcrypto_mpi_init( &S ); mbedcrypto_mpi_init( &T ); mbedcrypto_mpi_init( &U );

    /* Special case for A = -3 */
    if( grp->A.p == NULL )
    {
        /* M = 3(X + Z^2)(X - Z^2) */
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S,  &P->Z,  &P->Z   ) ); MOD_MUL( S );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &T,  &P->X,  &S      ) ); MOD_ADD( T );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &U,  &P->X,  &S      ) ); MOD_SUB( U );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S,  &T,     &U      ) ); MOD_MUL( S );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_int( &M,  &S,     3       ) ); MOD_ADD( M );
    }
    else
    {
        /* M = 3.X^2 */
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S,  &P->X,  &P->X   ) ); MOD_MUL( S );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_int( &M,  &S,     3       ) ); MOD_ADD( M );

        /* Optimize away for "koblitz" curves with A = 0 */
        if( mbedcrypto_mpi_cmp_int( &grp->A, 0 ) != 0 )
        {
            /* M += A.Z^4 */
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S,  &P->Z,  &P->Z   ) ); MOD_MUL( S );
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T,  &S,     &S      ) ); MOD_MUL( T );
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S,  &T,     &grp->A ) ); MOD_MUL( S );
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &M,  &M,     &S      ) ); MOD_ADD( M );
        }
    }

    /* S = 4.X.Y^2 */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T,  &P->Y,  &P->Y   ) ); MOD_MUL( T );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_l( &T,  1               ) ); MOD_ADD( T );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S,  &P->X,  &T      ) ); MOD_MUL( S );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_l( &S,  1               ) ); MOD_ADD( S );

    /* U = 8.Y^4 */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &U,  &T,     &T      ) ); MOD_MUL( U );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_l( &U,  1               ) ); MOD_ADD( U );

    /* T = M^2 - 2.S */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T,  &M,     &M      ) ); MOD_MUL( T );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &T,  &T,     &S      ) ); MOD_SUB( T );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &T,  &T,     &S      ) ); MOD_SUB( T );

    /* S = M(S - T) - U */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &S,  &S,     &T      ) ); MOD_SUB( S );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S,  &S,     &M      ) ); MOD_MUL( S );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &S,  &S,     &U      ) ); MOD_SUB( S );

    /* U = 2.Y.Z */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &U,  &P->Y,  &P->Z   ) ); MOD_MUL( U );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_l( &U,  1               ) ); MOD_ADD( U );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &R->X, &T ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &R->Y, &S ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &R->Z, &U ) );

cleanup:
    mbedcrypto_mpi_free( &M ); mbedcrypto_mpi_free( &S ); mbedcrypto_mpi_free( &T ); mbedcrypto_mpi_free( &U );

    return( ret );
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S
 */
static int ecp_add_mixed( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *R,
                          const mbedcrypto_ecp_point *P, const mbedcrypto_ecp_point *Q )
{
    int ret;
    mbedcrypto_mpi T1, T2, T3, T4, X, Y, Z;

#if defined(MBEDCRYPTO_SELF_TEST)
    add_count++;
#endif

#if defined(MBEDCRYPTO_ECP_ADD_MIXED_ALT)
    if ( mbedcrypto_internal_ecp_grp_capable( grp ) )
    {
        return mbedcrypto_internal_ecp_add_mixed( grp, R, P, Q );
    }
#endif /* MBEDCRYPTO_ECP_ADD_MIXED_ALT */

    /*
     * Trivial cases: P == 0 or Q == 0 (case 1)
     */
    if( mbedcrypto_mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( mbedcrypto_ecp_copy( R, Q ) );

    if( Q->Z.p != NULL && mbedcrypto_mpi_cmp_int( &Q->Z, 0 ) == 0 )
        return( mbedcrypto_ecp_copy( R, P ) );

    /*
     * Make sure Q coordinates are normalized
     */
    if( Q->Z.p != NULL && mbedcrypto_mpi_cmp_int( &Q->Z, 1 ) != 0 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    mbedcrypto_mpi_init( &T1 ); mbedcrypto_mpi_init( &T2 ); mbedcrypto_mpi_init( &T3 ); mbedcrypto_mpi_init( &T4 );
    mbedcrypto_mpi_init( &X ); mbedcrypto_mpi_init( &Y ); mbedcrypto_mpi_init( &Z );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) );  MOD_MUL( T1 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T2,  &T1,    &P->Z ) );  MOD_MUL( T2 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T1,  &T1,    &Q->X ) );  MOD_MUL( T1 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T2,  &T2,    &Q->Y ) );  MOD_MUL( T2 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &T1,  &T1,    &P->X ) );  MOD_SUB( T1 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &T2,  &T2,    &P->Y ) );  MOD_SUB( T2 );

    /* Special cases (2) and (3) */
    if( mbedcrypto_mpi_cmp_int( &T1, 0 ) == 0 )
    {
        if( mbedcrypto_mpi_cmp_int( &T2, 0 ) == 0 )
        {
            ret = ecp_double_jac( grp, R, P );
            goto cleanup;
        }
        else
        {
            ret = mbedcrypto_ecp_set_zero( R );
            goto cleanup;
        }
    }

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &Z,   &P->Z,  &T1   ) );  MOD_MUL( Z  );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T3,  &T1,    &T1   ) );  MOD_MUL( T3 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T4,  &T3,    &T1   ) );  MOD_MUL( T4 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T3,  &T3,    &P->X ) );  MOD_MUL( T3 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_int( &T1,  &T3,    2     ) );  MOD_ADD( T1 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &X,   &T2,    &T2   ) );  MOD_MUL( X  );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &X,   &X,     &T1   ) );  MOD_SUB( X  );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &X,   &X,     &T4   ) );  MOD_SUB( X  );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &T3,  &T3,    &X    ) );  MOD_SUB( T3 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T3,  &T3,    &T2   ) );  MOD_MUL( T3 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &T4,  &T4,    &P->Y ) );  MOD_MUL( T4 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &Y,   &T3,    &T4   ) );  MOD_SUB( Y  );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &R->X, &X ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &R->Y, &Y ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &R->Z, &Z ) );

cleanup:

    mbedcrypto_mpi_free( &T1 ); mbedcrypto_mpi_free( &T2 ); mbedcrypto_mpi_free( &T3 ); mbedcrypto_mpi_free( &T4 );
    mbedcrypto_mpi_free( &X ); mbedcrypto_mpi_free( &Y ); mbedcrypto_mpi_free( &Z );

    return( ret );
}

/*
 * Randomize jacobian coordinates:
 * (X, Y, Z) -> (l^2 X, l^3 Y, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_jac().
 *
 * This countermeasure was first suggested in [2].
 */
static int ecp_randomize_jac( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *pt,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    mbedcrypto_mpi l, ll;
    size_t p_size;
    int count = 0;

#if defined(MBEDCRYPTO_ECP_RANDOMIZE_JAC_ALT)
    if ( mbedcrypto_internal_ecp_grp_capable( grp ) )
    {
        return mbedcrypto_internal_ecp_randomize_jac( grp, pt, f_rng, p_rng );
    }
#endif /* MBEDCRYPTO_ECP_RANDOMIZE_JAC_ALT */

    p_size = ( grp->pbits + 7 ) / 8;
    mbedcrypto_mpi_init( &l ); mbedcrypto_mpi_init( &ll );

    /* Generate l such that 1 < l < p */
    do
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_fill_random( &l, p_size, f_rng, p_rng ) );

        while( mbedcrypto_mpi_cmp_mpi( &l, &grp->P ) >= 0 )
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_r( &l, 1 ) );

        if( count++ > 10 )
            return( MBEDCRYPTO_ERR_ECP_RANDOM_FAILED );
    }
    while( mbedcrypto_mpi_cmp_int( &l, 1 ) <= 0 );

    /* Z = l * Z */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &pt->Z,   &pt->Z,     &l  ) ); MOD_MUL( pt->Z );

    /* X = l^2 * X */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &ll,      &l,         &l  ) ); MOD_MUL( ll );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &pt->X,   &pt->X,     &ll ) ); MOD_MUL( pt->X );

    /* Y = l^3 * Y */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &ll,      &ll,        &l  ) ); MOD_MUL( ll );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &pt->Y,   &pt->Y,     &ll ) ); MOD_MUL( pt->Y );

cleanup:
    mbedcrypto_mpi_free( &l ); mbedcrypto_mpi_free( &ll );

    return( ret );
}

/*
 * Check and define parameters used by the comb method (see below for details)
 */
#if MBEDCRYPTO_ECP_WINDOW_SIZE < 2 || MBEDCRYPTO_ECP_WINDOW_SIZE > 7
#error "MBEDCRYPTO_ECP_WINDOW_SIZE out of bounds"
#endif

/* d = ceil( n / w ) */
#define COMB_MAX_D      ( MBEDCRYPTO_ECP_MAX_BITS + 1 ) / 2

/* number of precomputed points */
#define COMB_MAX_PRE    ( 1 << ( MBEDCRYPTO_ECP_WINDOW_SIZE - 1 ) )

/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries.
 *
 * Also, for the sake of compactness, only the seven low-order bits of x[i]
 * are used to represent K_i, and the msb of x[i] encodes the the sign (s_i in
 * the paper): it is set if and only if if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and MBEDCRYPTO_ECP_WINDOW_SIZE)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
static void ecp_comb_fixed( unsigned char x[], size_t d,
                            unsigned char w, const mbedcrypto_mpi *m )
{
    size_t i, j;
    unsigned char c, cc, adjust;

    memset( x, 0, d+1 );

    /* First get the classical comb values (except for x_d = 0) */
    for( i = 0; i < d; i++ )
        for( j = 0; j < w; j++ )
            x[i] |= mbedcrypto_mpi_get_bit( m, i + d * j ) << j;

    /* Now make sure x_1 .. x_d are odd */
    c = 0;
    for( i = 1; i <= d; i++ )
    {
        /* Add carry and update it */
        cc   = x[i] & c;
        x[i] = x[i] ^ c;
        c = cc;

        /* Adjust if needed, avoiding branches */
        adjust = 1 - ( x[i] & 0x01 );
        c   |= x[i] & ( x[i-1] * adjust );
        x[i] = x[i] ^ ( x[i-1] * adjust );
        x[i-1] |= adjust << 7;
    }
}

/*
 * Precompute points for the comb method
 *
 * If i = i_{w-1} ... i_1 is the binary representation of i, then
 * T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P
 *
 * T must be able to hold 2^{w - 1} elements
 *
 * Cost: d(w-1) D + (2^{w-1} - 1) A + 1 N(w-1) + 1 N(2^{w-1} - 1)
 */
static int ecp_precompute_comb( const mbedcrypto_ecp_group *grp,
                                mbedcrypto_ecp_point T[], const mbedcrypto_ecp_point *P,
                                unsigned char w, size_t d )
{
    int ret;
    unsigned char i, k;
    size_t j;
    mbedcrypto_ecp_point *cur, *TT[COMB_MAX_PRE - 1];

    /*
     * Set T[0] = P and
     * T[2^{l-1}] = 2^{dl} P for l = 1 .. w-1 (this is not the final value)
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_copy( &T[0], P ) );

    k = 0;
    for( i = 1; i < ( 1U << ( w - 1 ) ); i <<= 1 )
    {
        cur = T + i;
        MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_copy( cur, T + ( i >> 1 ) ) );
        for( j = 0; j < d; j++ )
            MBEDCRYPTO_MPI_CHK( ecp_double_jac( grp, cur, cur ) );

        TT[k++] = cur;
    }

    MBEDCRYPTO_MPI_CHK( ecp_normalize_jac_many( grp, TT, k ) );

    /*
     * Compute the remaining ones using the minimal number of additions
     * Be careful to update T[2^l] only after using it!
     */
    k = 0;
    for( i = 1; i < ( 1U << ( w - 1 ) ); i <<= 1 )
    {
        j = i;
        while( j-- )
        {
            MBEDCRYPTO_MPI_CHK( ecp_add_mixed( grp, &T[i + j], &T[j], &T[i] ) );
            TT[k++] = &T[i + j];
        }
    }

    MBEDCRYPTO_MPI_CHK( ecp_normalize_jac_many( grp, TT, k ) );

cleanup:

    return( ret );
}

/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 */
static int ecp_select_comb( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *R,
                            const mbedcrypto_ecp_point T[], unsigned char t_len,
                            unsigned char i )
{
    int ret;
    unsigned char ii, j;

    /* Ignore the "sign" bit and scale down */
    ii =  ( i & 0x7Fu ) >> 1;

    /* Read the whole table to thwart cache-based timing attacks */
    for( j = 0; j < t_len; j++ )
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_safe_cond_assign( &R->X, &T[j].X, j == ii ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_safe_cond_assign( &R->Y, &T[j].Y, j == ii ) );
    }

    /* Safely invert result if i is "negative" */
    MBEDCRYPTO_MPI_CHK( ecp_safe_invert_jac( grp, R, i >> 7 ) );

cleanup:
    return( ret );
}

/*
 * Core multiplication algorithm for the (modified) comb method.
 * This part is actually common with the basic comb method (GECC 3.44)
 *
 * Cost: d A + d D + 1 R
 */
static int ecp_mul_comb_core( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *R,
                              const mbedcrypto_ecp_point T[], unsigned char t_len,
                              const unsigned char x[], size_t d,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    int ret;
    mbedcrypto_ecp_point Txi;
    size_t i;

    mbedcrypto_ecp_point_init( &Txi );

    /* Start with a non-zero point and randomize its coordinates */
    i = d;
    MBEDCRYPTO_MPI_CHK( ecp_select_comb( grp, R, T, t_len, x[i] ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &R->Z, 1 ) );
    if( f_rng != 0 )
        MBEDCRYPTO_MPI_CHK( ecp_randomize_jac( grp, R, f_rng, p_rng ) );

    while( i-- != 0 )
    {
        MBEDCRYPTO_MPI_CHK( ecp_double_jac( grp, R, R ) );
        MBEDCRYPTO_MPI_CHK( ecp_select_comb( grp, &Txi, T, t_len, x[i] ) );
        MBEDCRYPTO_MPI_CHK( ecp_add_mixed( grp, R, R, &Txi ) );
    }

cleanup:

    mbedcrypto_ecp_point_free( &Txi );

    return( ret );
}

/*
 * Multiplication using the comb method,
 * for curves in short Weierstrass form
 */
static int ecp_mul_comb( mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *R,
                         const mbedcrypto_mpi *m, const mbedcrypto_ecp_point *P,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    int ret;
    unsigned char w, m_is_odd, p_eq_g, pre_len, i;
    size_t d;
    unsigned char k[COMB_MAX_D + 1];
    mbedcrypto_ecp_point *T;
    mbedcrypto_mpi M, mm;

    mbedcrypto_mpi_init( &M );
    mbedcrypto_mpi_init( &mm );

    /* we need N to be odd to trnaform m in an odd number, check now */
    if( mbedcrypto_mpi_get_bit( &grp->N, 0 ) != 1 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Minimize the number of multiplications, that is minimize
     * 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil( nbits / w )
     * (see costs of the various parts, with 1S = 1M)
     */
    w = grp->nbits >= 384 ? 5 : 4;

    /*
     * If P == G, pre-compute a bit more, since this may be re-used later.
     * Just adding one avoids upping the cost of the first mul too much,
     * and the memory cost too.
     */
#if MBEDCRYPTO_ECP_FIXED_POINT_OPTIM == 1
    p_eq_g = ( mbedcrypto_mpi_cmp_mpi( &P->Y, &grp->G.Y ) == 0 &&
               mbedcrypto_mpi_cmp_mpi( &P->X, &grp->G.X ) == 0 );
    if( p_eq_g )
        w++;
#else
    p_eq_g = 0;
#endif

    /*
     * Make sure w is within bounds.
     * (The last test is useful only for very small curves in the test suite.)
     */
    if( w > MBEDCRYPTO_ECP_WINDOW_SIZE )
        w = MBEDCRYPTO_ECP_WINDOW_SIZE;
    if( w >= grp->nbits )
        w = 2;

    /* Other sizes that depend on w */
    pre_len = 1U << ( w - 1 );
    d = ( grp->nbits + w - 1 ) / w;

    /*
     * Prepare precomputed points: if P == G we want to
     * use grp->T if already initialized, or initialize it.
     */
    T = p_eq_g ? grp->T : NULL;

    if( T == NULL )
    {
        T = mbedcrypto_calloc( pre_len, sizeof( mbedcrypto_ecp_point ) );
        if( T == NULL )
        {
            ret = MBEDCRYPTO_ERR_ECP_ALLOC_FAILED;
            goto cleanup;
        }

        MBEDCRYPTO_MPI_CHK( ecp_precompute_comb( grp, T, P, w, d ) );

        if( p_eq_g )
        {
            grp->T = T;
            grp->T_size = pre_len;
        }
    }

    /*
     * Make sure M is odd (M = m or M = N - m, since N is odd)
     * using the fact that m * P = - (N - m) * P
     */
    m_is_odd = ( mbedcrypto_mpi_get_bit( m, 0 ) == 1 );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &M, m ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &mm, &grp->N, m ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_safe_cond_assign( &M, &mm, ! m_is_odd ) );

    /*
     * Go for comb multiplication, R = M * P
     */
    ecp_comb_fixed( k, d, w, &M );
    MBEDCRYPTO_MPI_CHK( ecp_mul_comb_core( grp, R, T, pre_len, k, d, f_rng, p_rng ) );

    /*
     * Now get m * P from M * P and normalize it
     */
    MBEDCRYPTO_MPI_CHK( ecp_safe_invert_jac( grp, R, ! m_is_odd ) );
    MBEDCRYPTO_MPI_CHK( ecp_normalize_jac( grp, R ) );

cleanup:

    if( T != NULL && ! p_eq_g )
    {
        for( i = 0; i < pre_len; i++ )
            mbedcrypto_ecp_point_free( &T[i] );
        mbedcrypto_free( T );
    }

    mbedcrypto_mpi_free( &M );
    mbedcrypto_mpi_free( &mm );

    if( ret != 0 )
        mbedcrypto_ecp_point_free( R );

    return( ret );
}

#endif /* ECP_SHORTWEIERSTRASS */

#if defined(ECP_MONTGOMERY)
/*
 * For Montgomery curves, we do all the internal arithmetic in projective
 * coordinates. Import/export of points uses only the x coordinates, which is
 * internaly represented as X / Z.
 *
 * For scalar multiplication, we'll use a Montgomery ladder.
 */

/*
 * Normalize Montgomery x/z coordinates: X = X/Z, Z = 1
 * Cost: 1M + 1I
 */
static int ecp_normalize_mxz( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *P )
{
    int ret;

#if defined(MBEDCRYPTO_ECP_NORMALIZE_MXZ_ALT)
    if ( mbedcrypto_internal_ecp_grp_capable( grp ) )
    {
        return mbedcrypto_internal_ecp_normalize_mxz( grp, P );
    }
#endif /* MBEDCRYPTO_ECP_NORMALIZE_MXZ_ALT */

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_inv_mod( &P->Z, &P->Z, &grp->P ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &P->X, &P->X, &P->Z ) ); MOD_MUL( P->X );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &P->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Randomize projective x/z coordinates:
 * (X, Z) -> (l X, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_mxz().
 *
 * This countermeasure was first suggested in [2].
 * Cost: 2M
 */
static int ecp_randomize_mxz( const mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *P,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    mbedcrypto_mpi l;
    size_t p_size;
    int count = 0;

#if defined(MBEDCRYPTO_ECP_RANDOMIZE_MXZ_ALT)
    if ( mbedcrypto_internal_ecp_grp_capable( grp ) )
    {
        return mbedcrypto_internal_ecp_randomize_mxz( grp, P, f_rng, p_rng );
    }
#endif /* MBEDCRYPTO_ECP_RANDOMIZE_MXZ_ALT */

    p_size = ( grp->pbits + 7 ) / 8;
    mbedcrypto_mpi_init( &l );

    /* Generate l such that 1 < l < p */
    do
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_fill_random( &l, p_size, f_rng, p_rng ) );

        while( mbedcrypto_mpi_cmp_mpi( &l, &grp->P ) >= 0 )
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_r( &l, 1 ) );

        if( count++ > 10 )
            return( MBEDCRYPTO_ERR_ECP_RANDOM_FAILED );
    }
    while( mbedcrypto_mpi_cmp_int( &l, 1 ) <= 0 );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &P->X, &P->X, &l ) ); MOD_MUL( P->X );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &P->Z, &P->Z, &l ) ); MOD_MUL( P->Z );

cleanup:
    mbedcrypto_mpi_free( &l );

    return( ret );
}

/*
 * Double-and-add: R = 2P, S = P + Q, with d = X(P - Q),
 * for Montgomery curves in x/z coordinates.
 *
 * http://www.hyperelliptic.org/EFD/g1p/auto-code/montgom/xz/ladder/mladd-1987-m.op3
 * with
 * d =  X1
 * P = (X2, Z2)
 * Q = (X3, Z3)
 * R = (X4, Z4)
 * S = (X5, Z5)
 * and eliminating temporary variables tO, ..., t4.
 *
 * Cost: 5M + 4S
 */
static int ecp_double_add_mxz( const mbedcrypto_ecp_group *grp,
                               mbedcrypto_ecp_point *R, mbedcrypto_ecp_point *S,
                               const mbedcrypto_ecp_point *P, const mbedcrypto_ecp_point *Q,
                               const mbedcrypto_mpi *d )
{
    int ret;
    mbedcrypto_mpi A, AA, B, BB, E, C, D, DA, CB;

#if defined(MBEDCRYPTO_ECP_DOUBLE_ADD_MXZ_ALT)
    if ( mbedcrypto_internal_ecp_grp_capable( grp ) )
    {
        return mbedcrypto_internal_ecp_double_add_mxz( grp, R, S, P, Q, d );
    }
#endif /* MBEDCRYPTO_ECP_DOUBLE_ADD_MXZ_ALT */

    mbedcrypto_mpi_init( &A ); mbedcrypto_mpi_init( &AA ); mbedcrypto_mpi_init( &B );
    mbedcrypto_mpi_init( &BB ); mbedcrypto_mpi_init( &E ); mbedcrypto_mpi_init( &C );
    mbedcrypto_mpi_init( &D ); mbedcrypto_mpi_init( &DA ); mbedcrypto_mpi_init( &CB );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &A,    &P->X,   &P->Z ) ); MOD_ADD( A    );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &AA,   &A,      &A    ) ); MOD_MUL( AA   );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &B,    &P->X,   &P->Z ) ); MOD_SUB( B    );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &BB,   &B,      &B    ) ); MOD_MUL( BB   );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &E,    &AA,     &BB   ) ); MOD_SUB( E    );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &C,    &Q->X,   &Q->Z ) ); MOD_ADD( C    );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &D,    &Q->X,   &Q->Z ) ); MOD_SUB( D    );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &DA,   &D,      &A    ) ); MOD_MUL( DA   );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &CB,   &C,      &B    ) ); MOD_MUL( CB   );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &S->X, &DA,     &CB   ) ); MOD_MUL( S->X );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S->X, &S->X,   &S->X ) ); MOD_MUL( S->X );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &S->Z, &DA,     &CB   ) ); MOD_SUB( S->Z );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S->Z, &S->Z,   &S->Z ) ); MOD_MUL( S->Z );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &S->Z, d,       &S->Z ) ); MOD_MUL( S->Z );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &R->X, &AA,     &BB   ) ); MOD_MUL( R->X );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &R->Z, &grp->A, &E    ) ); MOD_MUL( R->Z );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &R->Z, &BB,     &R->Z ) ); MOD_ADD( R->Z );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &R->Z, &E,      &R->Z ) ); MOD_MUL( R->Z );

cleanup:
    mbedcrypto_mpi_free( &A ); mbedcrypto_mpi_free( &AA ); mbedcrypto_mpi_free( &B );
    mbedcrypto_mpi_free( &BB ); mbedcrypto_mpi_free( &E ); mbedcrypto_mpi_free( &C );
    mbedcrypto_mpi_free( &D ); mbedcrypto_mpi_free( &DA ); mbedcrypto_mpi_free( &CB );

    return( ret );
}

/*
 * Multiplication with Montgomery ladder in x/z coordinates,
 * for curves in Montgomery form
 */
static int ecp_mul_mxz( mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *R,
                        const mbedcrypto_mpi *m, const mbedcrypto_ecp_point *P,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng )
{
    int ret;
    size_t i;
    unsigned char b;
    mbedcrypto_ecp_point RP;
    mbedcrypto_mpi PX;

    mbedcrypto_ecp_point_init( &RP ); mbedcrypto_mpi_init( &PX );

    /* Save PX and read from P before writing to R, in case P == R */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_copy( &PX, &P->X ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_copy( &RP, P ) );

    /* Set R to zero in modified x/z coordinates */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &R->X, 1 ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &R->Z, 0 ) );
    mbedcrypto_mpi_free( &R->Y );

    /* RP.X might be sligtly larger than P, so reduce it */
    MOD_ADD( RP.X );

    /* Randomize coordinates of the starting point */
    if( f_rng != NULL )
        MBEDCRYPTO_MPI_CHK( ecp_randomize_mxz( grp, &RP, f_rng, p_rng ) );

    /* Loop invariant: R = result so far, RP = R + P */
    i = mbedcrypto_mpi_bitlen( m ); /* one past the (zero-based) most significant bit */
    while( i-- > 0 )
    {
        b = mbedcrypto_mpi_get_bit( m, i );
        /*
         *  if (b) R = 2R + P else R = 2R,
         * which is:
         *  if (b) double_add( RP, R, RP, R )
         *  else   double_add( R, RP, R, RP )
         * but using safe conditional swaps to avoid leaks
         */
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_safe_cond_swap( &R->X, &RP.X, b ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_safe_cond_swap( &R->Z, &RP.Z, b ) );
        MBEDCRYPTO_MPI_CHK( ecp_double_add_mxz( grp, R, &RP, R, &RP, &PX ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_safe_cond_swap( &R->X, &RP.X, b ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_safe_cond_swap( &R->Z, &RP.Z, b ) );
    }

    MBEDCRYPTO_MPI_CHK( ecp_normalize_mxz( grp, R ) );

cleanup:
    mbedcrypto_ecp_point_free( &RP ); mbedcrypto_mpi_free( &PX );

    return( ret );
}

#endif /* ECP_MONTGOMERY */

/*
 * Multiplication R = m * P
 */
int mbedcrypto_ecp_mul( mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *R,
             const mbedcrypto_mpi *m, const mbedcrypto_ecp_point *P,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA;
#if defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
    char is_grp_capable = 0;
#endif

    /* Common sanity checks */
    if( mbedcrypto_mpi_cmp_int( &P->Z, 1 ) != 0 )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedcrypto_ecp_check_privkey( grp, m ) ) != 0 ||
        ( ret = mbedcrypto_ecp_check_pubkey( grp, P ) ) != 0 )
        return( ret );

#if defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
    if ( is_grp_capable = mbedcrypto_internal_ecp_grp_capable( grp )  )
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_internal_ecp_init( grp ) );
    }

#endif /* MBEDCRYPTO_ECP_INTERNAL_ALT */
#if defined(ECP_MONTGOMERY)
    if( ecp_get_type( grp ) == ECP_TYPE_MONTGOMERY )
        ret = ecp_mul_mxz( grp, R, m, P, f_rng, p_rng );

#endif
#if defined(ECP_SHORTWEIERSTRASS)
    if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
        ret = ecp_mul_comb( grp, R, m, P, f_rng, p_rng );

#endif
#if defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
cleanup:

    if ( is_grp_capable )
    {
        mbedcrypto_internal_ecp_free( grp );
    }

#endif /* MBEDCRYPTO_ECP_INTERNAL_ALT */
    return( ret );
}

#if defined(ECP_SHORTWEIERSTRASS)
/*
 * Check that an affine point is valid as a public key,
 * short weierstrass curves (SEC1 3.2.3.1)
 */
static int ecp_check_pubkey_sw( const mbedcrypto_ecp_group *grp, const mbedcrypto_ecp_point *pt )
{
    int ret;
    mbedcrypto_mpi YY, RHS;

    /* pt coordinates must be normalized for our checks */
    if( mbedcrypto_mpi_cmp_int( &pt->X, 0 ) < 0 ||
        mbedcrypto_mpi_cmp_int( &pt->Y, 0 ) < 0 ||
        mbedcrypto_mpi_cmp_mpi( &pt->X, &grp->P ) >= 0 ||
        mbedcrypto_mpi_cmp_mpi( &pt->Y, &grp->P ) >= 0 )
        return( MBEDCRYPTO_ERR_ECP_INVALID_KEY );

    mbedcrypto_mpi_init( &YY ); mbedcrypto_mpi_init( &RHS );

    /*
     * YY = Y^2
     * RHS = X (X^2 + A) + B = X^3 + A X + B
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &YY,  &pt->Y,   &pt->Y  ) );  MOD_MUL( YY  );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &RHS, &pt->X,   &pt->X  ) );  MOD_MUL( RHS );

    /* Special case for A = -3 */
    if( grp->A.p == NULL )
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_int( &RHS, &RHS, 3       ) );  MOD_SUB( RHS );
    }
    else
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &RHS, &RHS, &grp->A ) );  MOD_ADD( RHS );
    }

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &RHS, &RHS,     &pt->X  ) );  MOD_MUL( RHS );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &RHS, &RHS,     &grp->B ) );  MOD_ADD( RHS );

    if( mbedcrypto_mpi_cmp_mpi( &YY, &RHS ) != 0 )
        ret = MBEDCRYPTO_ERR_ECP_INVALID_KEY;

cleanup:

    mbedcrypto_mpi_free( &YY ); mbedcrypto_mpi_free( &RHS );

    return( ret );
}
#endif /* ECP_SHORTWEIERSTRASS */

/*
 * R = m * P with shortcuts for m == 1 and m == -1
 * NOT constant-time - ONLY for short Weierstrass!
 */
static int mbedcrypto_ecp_mul_shortcuts( mbedcrypto_ecp_group *grp,
                                      mbedcrypto_ecp_point *R,
                                      const mbedcrypto_mpi *m,
                                      const mbedcrypto_ecp_point *P )
{
    int ret;

    if( mbedcrypto_mpi_cmp_int( m, 1 ) == 0 )
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_copy( R, P ) );
    }
    else if( mbedcrypto_mpi_cmp_int( m, -1 ) == 0 )
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_copy( R, P ) );
        if( mbedcrypto_mpi_cmp_int( &R->Y, 0 ) != 0 )
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( &R->Y, &grp->P, &R->Y ) );
    }
    else
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul( grp, R, m, P, NULL, NULL ) );
    }

cleanup:
    return( ret );
}

/*
 * Linear combination
 * NOT constant-time
 */
int mbedcrypto_ecp_muladd( mbedcrypto_ecp_group *grp, mbedcrypto_ecp_point *R,
             const mbedcrypto_mpi *m, const mbedcrypto_ecp_point *P,
             const mbedcrypto_mpi *n, const mbedcrypto_ecp_point *Q )
{
    int ret;
    mbedcrypto_ecp_point mP;
#if defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
    char is_grp_capable = 0;
#endif

    if( ecp_get_type( grp ) != ECP_TYPE_SHORT_WEIERSTRASS )
        return( MBEDCRYPTO_ERR_ECP_FEATURE_UNAVAILABLE );

    mbedcrypto_ecp_point_init( &mP );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul_shortcuts( grp, &mP, m, P ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul_shortcuts( grp, R,   n, Q ) );

#if defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
    if (  is_grp_capable = mbedcrypto_internal_ecp_grp_capable( grp )  )
    {
        MBEDCRYPTO_MPI_CHK( mbedcrypto_internal_ecp_init( grp ) );
    }

#endif /* MBEDCRYPTO_ECP_INTERNAL_ALT */
    MBEDCRYPTO_MPI_CHK( ecp_add_mixed( grp, R, &mP, R ) );
    MBEDCRYPTO_MPI_CHK( ecp_normalize_jac( grp, R ) );

cleanup:

#if defined(MBEDCRYPTO_ECP_INTERNAL_ALT)
    if ( is_grp_capable )
    {
        mbedcrypto_internal_ecp_free( grp );
    }

#endif /* MBEDCRYPTO_ECP_INTERNAL_ALT */
    mbedcrypto_ecp_point_free( &mP );

    return( ret );
}


#if defined(ECP_MONTGOMERY)
/*
 * Check validity of a public key for Montgomery curves with x-only schemes
 */
static int ecp_check_pubkey_mx( const mbedcrypto_ecp_group *grp, const mbedcrypto_ecp_point *pt )
{
    /* [Curve25519 p. 5] Just check X is the correct number of bytes */
    /* Allow any public value, if it's too big then we'll just reduce it mod p
     * (RFC 7748 sec. 5 para. 3). */
    if( mbedcrypto_mpi_size( &pt->X ) > ( grp->nbits + 7 ) / 8 )
        return( MBEDCRYPTO_ERR_ECP_INVALID_KEY );

    return( 0 );
}
#endif /* ECP_MONTGOMERY */

/*
 * Check that a point is valid as a public key
 */
int mbedcrypto_ecp_check_pubkey( const mbedcrypto_ecp_group *grp, const mbedcrypto_ecp_point *pt )
{
    /* Must use affine coordinates */
    if( mbedcrypto_mpi_cmp_int( &pt->Z, 1 ) != 0 )
        return( MBEDCRYPTO_ERR_ECP_INVALID_KEY );

#if defined(ECP_MONTGOMERY)
    if( ecp_get_type( grp ) == ECP_TYPE_MONTGOMERY )
        return( ecp_check_pubkey_mx( grp, pt ) );
#endif
#if defined(ECP_SHORTWEIERSTRASS)
    if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
        return( ecp_check_pubkey_sw( grp, pt ) );
#endif
    return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );
}

/*
 * Check that an mbedcrypto_mpi is valid as a private key
 */
int mbedcrypto_ecp_check_privkey( const mbedcrypto_ecp_group *grp, const mbedcrypto_mpi *d )
{
#if defined(ECP_MONTGOMERY)
    if( ecp_get_type( grp ) == ECP_TYPE_MONTGOMERY )
    {
        /* see RFC 7748 sec. 5 para. 5 */
        if( mbedcrypto_mpi_get_bit( d, 0 ) != 0 ||
            mbedcrypto_mpi_get_bit( d, 1 ) != 0 ||
            mbedcrypto_mpi_bitlen( d ) - 1 != grp->nbits ) /* mbedcrypto_mpi_bitlen is one-based! */
            return( MBEDCRYPTO_ERR_ECP_INVALID_KEY );
        else

        /* see [Curve25519] page 5 */
        if( grp->nbits == 254 && mbedcrypto_mpi_get_bit( d, 2 ) != 0 )
            return( MBEDCRYPTO_ERR_ECP_INVALID_KEY );

        return( 0 );
    }
#endif /* ECP_MONTGOMERY */
#if defined(ECP_SHORTWEIERSTRASS)
    if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
    {
        /* see SEC1 3.2 */
        if( mbedcrypto_mpi_cmp_int( d, 1 ) < 0 ||
            mbedcrypto_mpi_cmp_mpi( d, &grp->N ) >= 0 )
            return( MBEDCRYPTO_ERR_ECP_INVALID_KEY );
        else
            return( 0 );
    }
#endif /* ECP_SHORTWEIERSTRASS */

    return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );
}

/*
 * Generate a keypair with configurable base point
 */
int mbedcrypto_ecp_gen_keypair_base( mbedcrypto_ecp_group *grp,
                     const mbedcrypto_ecp_point *G,
                     mbedcrypto_mpi *d, mbedcrypto_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int ret;
    size_t n_size = ( grp->nbits + 7 ) / 8;

#if defined(ECP_MONTGOMERY)
    if( ecp_get_type( grp ) == ECP_TYPE_MONTGOMERY )
    {
        /* [M225] page 5 */
        size_t b;

        do {
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_fill_random( d, n_size, f_rng, p_rng ) );
        } while( mbedcrypto_mpi_bitlen( d ) == 0);

        /* Make sure the most significant bit is nbits */
        b = mbedcrypto_mpi_bitlen( d ) - 1; /* mbedcrypto_mpi_bitlen is one-based */
        if( b > grp->nbits )
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_r( d, b - grp->nbits ) );
        else
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_set_bit( d, grp->nbits, 1 ) );

        /* Make sure the last two bits are unset for Curve448, three bits for
           Curve25519 */
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_set_bit( d, 0, 0 ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_set_bit( d, 1, 0 ) );
        if( grp->nbits == 254 )
        {
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_set_bit( d, 2, 0 ) );
        }
    }
    else
#endif /* ECP_MONTGOMERY */
#if defined(ECP_SHORTWEIERSTRASS)
    if( ecp_get_type( grp ) == ECP_TYPE_SHORT_WEIERSTRASS )
    {
        /* SEC1 3.2.1: Generate d such that 1 <= n < N */
        int count = 0;

        /*
         * Match the procedure given in RFC 6979 (deterministic ECDSA):
         * - use the same byte ordering;
         * - keep the leftmost nbits bits of the generated octet string;
         * - try until result is in the desired range.
         * This also avoids any biais, which is especially important for ECDSA.
         */
        do
        {
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_fill_random( d, n_size, f_rng, p_rng ) );
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_r( d, 8 * n_size - grp->nbits ) );

            /*
             * Each try has at worst a probability 1/2 of failing (the msb has
             * a probability 1/2 of being 0, and then the result will be < N),
             * so after 30 tries failure probability is a most 2**(-30).
             *
             * For most curves, 1 try is enough with overwhelming probability,
             * since N starts with a lot of 1s in binary, but some curves
             * such as secp224k1 are actually very close to the worst case.
             */
            if( ++count > 30 )
                return( MBEDCRYPTO_ERR_ECP_RANDOM_FAILED );
        }
        while( mbedcrypto_mpi_cmp_int( d, 1 ) < 0 ||
               mbedcrypto_mpi_cmp_mpi( d, &grp->N ) >= 0 );
    }
    else
#endif /* ECP_SHORTWEIERSTRASS */
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

cleanup:
    if( ret != 0 )
        return( ret );

    return( mbedcrypto_ecp_mul( grp, Q, d, G, f_rng, p_rng ) );
}

/*
 * Generate key pair, wrapper for conventional base point
 */
int mbedcrypto_ecp_gen_keypair( mbedcrypto_ecp_group *grp,
                             mbedcrypto_mpi *d, mbedcrypto_ecp_point *Q,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng )
{
    return( mbedcrypto_ecp_gen_keypair_base( grp, &grp->G, d, Q, f_rng, p_rng ) );
}

/*
 * Generate a keypair, prettier wrapper
 */
int mbedcrypto_ecp_gen_key( mbedcrypto_ecp_group_id grp_id, mbedcrypto_ecp_keypair *key,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;

    if( ( ret = mbedcrypto_ecp_group_load( &key->grp, grp_id ) ) != 0 )
        return( ret );

    return( mbedcrypto_ecp_gen_keypair( &key->grp, &key->d, &key->Q, f_rng, p_rng ) );
}

/*
 * Check a public-private key pair
 */
int mbedcrypto_ecp_check_pub_priv( const mbedcrypto_ecp_keypair *pub, const mbedcrypto_ecp_keypair *prv )
{
    int ret;
    mbedcrypto_ecp_point Q;
    mbedcrypto_ecp_group grp;

    if( pub->grp.id == MBEDCRYPTO_ECP_DP_NONE ||
        pub->grp.id != prv->grp.id ||
        mbedcrypto_mpi_cmp_mpi( &pub->Q.X, &prv->Q.X ) ||
        mbedcrypto_mpi_cmp_mpi( &pub->Q.Y, &prv->Q.Y ) ||
        mbedcrypto_mpi_cmp_mpi( &pub->Q.Z, &prv->Q.Z ) )
    {
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );
    }

    mbedcrypto_ecp_point_init( &Q );
    mbedcrypto_ecp_group_init( &grp );

    /* mbedcrypto_ecp_mul() needs a non-const group... */
    mbedcrypto_ecp_group_copy( &grp, &prv->grp );

    /* Also checks d is valid */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul( &grp, &Q, &prv->d, &prv->grp.G, NULL, NULL ) );

    if( mbedcrypto_mpi_cmp_mpi( &Q.X, &prv->Q.X ) ||
        mbedcrypto_mpi_cmp_mpi( &Q.Y, &prv->Q.Y ) ||
        mbedcrypto_mpi_cmp_mpi( &Q.Z, &prv->Q.Z ) )
    {
        ret = MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:
    mbedcrypto_ecp_point_free( &Q );
    mbedcrypto_ecp_group_free( &grp );

    return( ret );
}

#if defined(MBEDCRYPTO_SELF_TEST)

/*
 * Checkup routine
 */
int mbedcrypto_ecp_self_test( int verbose )
{
    int ret;
    size_t i;
    mbedcrypto_ecp_group grp;
    mbedcrypto_ecp_point R, P;
    mbedcrypto_mpi m;
    unsigned long add_c_prev, dbl_c_prev, mul_c_prev;
    /* exponents especially adapted for secp192r1 */
    const char *exponents[] =
    {
        "000000000000000000000000000000000000000000000001", /* one */
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22830", /* N - 1 */
        "5EA6F389A38B8BC81E767753B15AA5569E1782E30ABE7D25", /* random */
        "400000000000000000000000000000000000000000000000", /* one and zeros */
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", /* all ones */
        "555555555555555555555555555555555555555555555555", /* 101010... */
    };

    mbedcrypto_ecp_group_init( &grp );
    mbedcrypto_ecp_point_init( &R );
    mbedcrypto_ecp_point_init( &P );
    mbedcrypto_mpi_init( &m );

    /* Use secp192r1 if available, or any available curve */
#if defined(MBEDCRYPTO_ECP_DP_SECP192R1_ENABLED)
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_group_load( &grp, MBEDCRYPTO_ECP_DP_SECP192R1 ) );
#else
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_group_load( &grp, mbedcrypto_ecp_curve_list()->grp_id ) );
#endif

    if( verbose != 0 )
        mbedcrypto_printf( "  ECP test #1 (constant op_count, base point G): " );

    /* Do a dummy multiplication first to trigger precomputation */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_lset( &m, 2 ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul( &grp, &P, &m, &grp.G, NULL, NULL ) );

    add_count = 0;
    dbl_count = 0;
    mul_count = 0;
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_string( &m, 16, exponents[0] ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul( &grp, &R, &m, &grp.G, NULL, NULL ) );

    for( i = 1; i < sizeof( exponents ) / sizeof( exponents[0] ); i++ )
    {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        mul_c_prev = mul_count;
        add_count = 0;
        dbl_count = 0;
        mul_count = 0;

        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_string( &m, 16, exponents[i] ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul( &grp, &R, &m, &grp.G, NULL, NULL ) );

        if( add_count != add_c_prev ||
            dbl_count != dbl_c_prev ||
            mul_count != mul_c_prev )
        {
            if( verbose != 0 )
                mbedcrypto_printf( "failed (%u)\n", (unsigned int) i );

            ret = 1;
            goto cleanup;
        }
    }

    if( verbose != 0 )
        mbedcrypto_printf( "passed\n" );

    if( verbose != 0 )
        mbedcrypto_printf( "  ECP test #2 (constant op_count, other point): " );
    /* We computed P = 2G last time, use it */

    add_count = 0;
    dbl_count = 0;
    mul_count = 0;
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_string( &m, 16, exponents[0] ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul( &grp, &R, &m, &P, NULL, NULL ) );

    for( i = 1; i < sizeof( exponents ) / sizeof( exponents[0] ); i++ )
    {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        mul_c_prev = mul_count;
        add_count = 0;
        dbl_count = 0;
        mul_count = 0;

        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_string( &m, 16, exponents[i] ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_mul( &grp, &R, &m, &P, NULL, NULL ) );

        if( add_count != add_c_prev ||
            dbl_count != dbl_c_prev ||
            mul_count != mul_c_prev )
        {
            if( verbose != 0 )
                mbedcrypto_printf( "failed (%u)\n", (unsigned int) i );

            ret = 1;
            goto cleanup;
        }
    }

    if( verbose != 0 )
        mbedcrypto_printf( "passed\n" );

cleanup:

    if( ret < 0 && verbose != 0 )
        mbedcrypto_printf( "Unexpected error, return code = %08X\n", ret );

    mbedcrypto_ecp_group_free( &grp );
    mbedcrypto_ecp_point_free( &R );
    mbedcrypto_ecp_point_free( &P );
    mbedcrypto_mpi_free( &m );

    if( verbose != 0 )
        mbedcrypto_printf( "\n" );

    return( ret );
}

#endif /* MBEDCRYPTO_SELF_TEST */

#endif /* !MBEDCRYPTO_ECP_ALT */

#endif /* MBEDCRYPTO_ECP_C */
