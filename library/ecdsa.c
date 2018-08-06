/*
 *  Elliptic curve DSA
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
 */

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "mbedcrypto/config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#if defined(MBEDCRYPTO_ECDSA_C)

#include "mbedcrypto/ecdsa.h"
#include "mbedcrypto/asn1write.h"

#include <string.h>

#if defined(MBEDCRYPTO_ECDSA_DETERMINISTIC)
#include "mbedcrypto/hmac_drbg.h"
#endif

/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi( const mbedcrypto_ecp_group *grp, mbedcrypto_mpi *x,
                       const unsigned char *buf, size_t blen )
{
    int ret;
    size_t n_size = ( grp->nbits + 7 ) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_read_binary( x, buf, use_size ) );
    if( use_size * 8 > grp->nbits )
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_r( x, use_size * 8 - grp->nbits ) );

    /* While at it, reduce modulo N */
    if( mbedcrypto_mpi_cmp_mpi( x, &grp->N ) >= 0 )
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_sub_mpi( x, x, &grp->N ) );

cleanup:
    return( ret );
}

#if !defined(MBEDCRYPTO_ECDSA_SIGN_ALT)
/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int mbedcrypto_ecdsa_sign( mbedcrypto_ecp_group *grp, mbedcrypto_mpi *r, mbedcrypto_mpi *s,
                const mbedcrypto_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, key_tries, sign_tries, blind_tries;
    mbedcrypto_ecp_point R;
    mbedcrypto_mpi k, e, t;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    /* Make sure d is in range 1..n-1 */
    if( mbedcrypto_mpi_cmp_int( d, 1 ) < 0 || mbedcrypto_mpi_cmp_mpi( d, &grp->N ) >= 0 )
        return( MBEDCRYPTO_ERR_ECP_INVALID_KEY );

    mbedcrypto_ecp_point_init( &R );
    mbedcrypto_mpi_init( &k ); mbedcrypto_mpi_init( &e ); mbedcrypto_mpi_init( &t );

    sign_tries = 0;
    do
    {
        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        key_tries = 0;
        do
        {
            MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_gen_keypair( grp, &k, &R, f_rng, p_rng ) );
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mod_mpi( r, &R.X, &grp->N ) );

            if( key_tries++ > 10 )
            {
                ret = MBEDCRYPTO_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }
        }
        while( mbedcrypto_mpi_cmp_int( r, 0 ) == 0 );

        /*
         * Step 5: derive MPI from hashed message
         */
        MBEDCRYPTO_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

        /*
         * Generate a random value to blind inv_mod in next step,
         * avoiding a potential timing leak.
         */
        blind_tries = 0;
        do
        {
            size_t n_size = ( grp->nbits + 7 ) / 8;
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_fill_random( &t, n_size, f_rng, p_rng ) );
            MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_shift_r( &t, 8 * n_size - grp->nbits ) );

            /* See mbedcrypto_ecp_gen_keypair() */
            if( ++blind_tries > 30 )
                return( MBEDCRYPTO_ERR_ECP_RANDOM_FAILED );
        }
        while( mbedcrypto_mpi_cmp_int( &t, 1 ) < 0 ||
               mbedcrypto_mpi_cmp_mpi( &t, &grp->N ) >= 0 );

        /*
         * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
         */
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( s, r, d ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_add_mpi( &e, &e, s ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &e, &e, &t ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &k, &k, &t ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_inv_mod( s, &k, &grp->N ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( s, s, &e ) );
        MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mod_mpi( s, s, &grp->N ) );

        if( sign_tries++ > 10 )
        {
            ret = MBEDCRYPTO_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
    }
    while( mbedcrypto_mpi_cmp_int( s, 0 ) == 0 );

cleanup:
    mbedcrypto_ecp_point_free( &R );
    mbedcrypto_mpi_free( &k ); mbedcrypto_mpi_free( &e ); mbedcrypto_mpi_free( &t );

    return( ret );
}
#endif /* MBEDCRYPTO_ECDSA_SIGN_ALT */

#if defined(MBEDCRYPTO_ECDSA_DETERMINISTIC)
/*
 * Deterministic signature wrapper
 */
int mbedcrypto_ecdsa_sign_det( mbedcrypto_ecp_group *grp, mbedcrypto_mpi *r, mbedcrypto_mpi *s,
                    const mbedcrypto_mpi *d, const unsigned char *buf, size_t blen,
                    mbedcrypto_md_type_t md_alg )
{
    int ret;
    mbedcrypto_hmac_drbg_context rng_ctx;
    unsigned char data[2 * MBEDCRYPTO_ECP_MAX_BYTES];
    size_t grp_len = ( grp->nbits + 7 ) / 8;
    const mbedcrypto_md_info_t *md_info;
    mbedcrypto_mpi h;

    if( ( md_info = mbedcrypto_md_info_from_type( md_alg ) ) == NULL )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    mbedcrypto_mpi_init( &h );
    mbedcrypto_hmac_drbg_init( &rng_ctx );

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_write_binary( d, data, grp_len ) );
    MBEDCRYPTO_MPI_CHK( derive_mpi( grp, &h, buf, blen ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_write_binary( &h, data + grp_len, grp_len ) );
    mbedcrypto_hmac_drbg_seed_buf( &rng_ctx, md_info, data, 2 * grp_len );

    ret = mbedcrypto_ecdsa_sign( grp, r, s, d, buf, blen,
                      mbedcrypto_hmac_drbg_random, &rng_ctx );

cleanup:
    mbedcrypto_hmac_drbg_free( &rng_ctx );
    mbedcrypto_mpi_free( &h );

    return( ret );
}
#endif /* MBEDCRYPTO_ECDSA_DETERMINISTIC */

#if !defined(MBEDCRYPTO_ECDSA_VERIFY_ALT)
/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
int mbedcrypto_ecdsa_verify( mbedcrypto_ecp_group *grp,
                  const unsigned char *buf, size_t blen,
                  const mbedcrypto_ecp_point *Q, const mbedcrypto_mpi *r, const mbedcrypto_mpi *s)
{
    int ret;
    mbedcrypto_mpi e, s_inv, u1, u2;
    mbedcrypto_ecp_point R;

    mbedcrypto_ecp_point_init( &R );
    mbedcrypto_mpi_init( &e ); mbedcrypto_mpi_init( &s_inv ); mbedcrypto_mpi_init( &u1 ); mbedcrypto_mpi_init( &u2 );

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if( mbedcrypto_mpi_cmp_int( r, 1 ) < 0 || mbedcrypto_mpi_cmp_mpi( r, &grp->N ) >= 0 ||
        mbedcrypto_mpi_cmp_int( s, 1 ) < 0 || mbedcrypto_mpi_cmp_mpi( s, &grp->N ) >= 0 )
    {
        ret = MBEDCRYPTO_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Additional precaution: make sure Q is valid
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_check_pubkey( grp, Q ) );

    /*
     * Step 3: derive MPI from hashed message
     */
    MBEDCRYPTO_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

    /*
     * Step 4: u1 = e / s mod n, u2 = r / s mod n
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_inv_mod( &s_inv, s, &grp->N ) );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &u1, &e, &s_inv ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mod_mpi( &u1, &u1, &grp->N ) );

    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mul_mpi( &u2, r, &s_inv ) );
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mod_mpi( &u2, &u2, &grp->N ) );

    /*
     * Step 5: R = u1 G + u2 Q
     *
     * Since we're not using any secret data, no need to pass a RNG to
     * mbedcrypto_ecp_mul() for countermesures.
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecp_muladd( grp, &R, &u1, &grp->G, &u2, Q ) );

    if( mbedcrypto_ecp_is_zero( &R ) )
    {
        ret = MBEDCRYPTO_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n (gives v)
     */
    MBEDCRYPTO_MPI_CHK( mbedcrypto_mpi_mod_mpi( &R.X, &R.X, &grp->N ) );

    /*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if( mbedcrypto_mpi_cmp_mpi( &R.X, r ) != 0 )
    {
        ret = MBEDCRYPTO_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedcrypto_ecp_point_free( &R );
    mbedcrypto_mpi_free( &e ); mbedcrypto_mpi_free( &s_inv ); mbedcrypto_mpi_free( &u1 ); mbedcrypto_mpi_free( &u2 );

    return( ret );
}
#endif /* MBEDCRYPTO_ECDSA_VERIFY_ALT */

/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1( const mbedcrypto_mpi *r, const mbedcrypto_mpi *s,
                                    unsigned char *sig, size_t *slen )
{
    int ret;
    unsigned char buf[MBEDCRYPTO_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_mpi( &p, buf, s ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_mpi( &p, buf, r ) );

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( &p, buf, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( &p, buf,
                                       MBEDCRYPTO_ASN1_CONSTRUCTED | MBEDCRYPTO_ASN1_SEQUENCE ) );

    memcpy( sig, p, len );
    *slen = len;

    return( 0 );
}

/*
 * Compute and write signature
 */
int mbedcrypto_ecdsa_write_signature( mbedcrypto_ecdsa_context *ctx, mbedcrypto_md_type_t md_alg,
                           const unsigned char *hash, size_t hlen,
                           unsigned char *sig, size_t *slen,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng )
{
    int ret;
    mbedcrypto_mpi r, s;

    mbedcrypto_mpi_init( &r );
    mbedcrypto_mpi_init( &s );

#if defined(MBEDCRYPTO_ECDSA_DETERMINISTIC)
    (void) f_rng;
    (void) p_rng;

    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecdsa_sign_det( &ctx->grp, &r, &s, &ctx->d,
                             hash, hlen, md_alg ) );
#else
    (void) md_alg;

    MBEDCRYPTO_MPI_CHK( mbedcrypto_ecdsa_sign( &ctx->grp, &r, &s, &ctx->d,
                         hash, hlen, f_rng, p_rng ) );
#endif

    MBEDCRYPTO_MPI_CHK( ecdsa_signature_to_asn1( &r, &s, sig, slen ) );

cleanup:
    mbedcrypto_mpi_free( &r );
    mbedcrypto_mpi_free( &s );

    return( ret );
}

#if ! defined(MBEDCRYPTO_DEPRECATED_REMOVED) && \
    defined(MBEDCRYPTO_ECDSA_DETERMINISTIC)
int mbedcrypto_ecdsa_write_signature_det( mbedcrypto_ecdsa_context *ctx,
                               const unsigned char *hash, size_t hlen,
                               unsigned char *sig, size_t *slen,
                               mbedcrypto_md_type_t md_alg )
{
    return( mbedcrypto_ecdsa_write_signature( ctx, md_alg, hash, hlen, sig, slen,
                                   NULL, NULL ) );
}
#endif

/*
 * Read and check signature
 */
int mbedcrypto_ecdsa_read_signature( mbedcrypto_ecdsa_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen )
{
    int ret;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    mbedcrypto_mpi r, s;

    mbedcrypto_mpi_init( &r );
    mbedcrypto_mpi_init( &s );

    if( ( ret = mbedcrypto_asn1_get_tag( &p, end, &len,
                    MBEDCRYPTO_ASN1_CONSTRUCTED | MBEDCRYPTO_ASN1_SEQUENCE ) ) != 0 )
    {
        ret += MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( p + len != end )
    {
        ret = MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA +
              MBEDCRYPTO_ERR_ASN1_LENGTH_MISMATCH;
        goto cleanup;
    }

    if( ( ret = mbedcrypto_asn1_get_mpi( &p, end, &r ) ) != 0 ||
        ( ret = mbedcrypto_asn1_get_mpi( &p, end, &s ) ) != 0 )
    {
        ret += MBEDCRYPTO_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( ( ret = mbedcrypto_ecdsa_verify( &ctx->grp, hash, hlen,
                              &ctx->Q, &r, &s ) ) != 0 )
        goto cleanup;

    /* At this point we know that the buffer starts with a valid signature.
     * Return 0 if the buffer just contains the signature, and a specific
     * error code if the valid signature is followed by more data. */
    if( p != end )
        ret = MBEDCRYPTO_ERR_ECP_SIG_LEN_MISMATCH;

cleanup:
    mbedcrypto_mpi_free( &r );
    mbedcrypto_mpi_free( &s );

    return( ret );
}

#if !defined(MBEDCRYPTO_ECDSA_GENKEY_ALT)
/*
 * Generate key pair
 */
int mbedcrypto_ecdsa_genkey( mbedcrypto_ecdsa_context *ctx, mbedcrypto_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( mbedcrypto_ecp_group_load( &ctx->grp, gid ) ||
            mbedcrypto_ecp_gen_keypair( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) );
}
#endif /* MBEDCRYPTO_ECDSA_GENKEY_ALT */

/*
 * Set context from an mbedcrypto_ecp_keypair
 */
int mbedcrypto_ecdsa_from_keypair( mbedcrypto_ecdsa_context *ctx, const mbedcrypto_ecp_keypair *key )
{
    int ret;

    if( ( ret = mbedcrypto_ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 ||
        ( ret = mbedcrypto_mpi_copy( &ctx->d, &key->d ) ) != 0 ||
        ( ret = mbedcrypto_ecp_copy( &ctx->Q, &key->Q ) ) != 0 )
    {
        mbedcrypto_ecdsa_free( ctx );
    }

    return( ret );
}

/*
 * Initialize context
 */
void mbedcrypto_ecdsa_init( mbedcrypto_ecdsa_context *ctx )
{
    mbedcrypto_ecp_keypair_init( ctx );
}

/*
 * Free context
 */
void mbedcrypto_ecdsa_free( mbedcrypto_ecdsa_context *ctx )
{
    mbedcrypto_ecp_keypair_free( ctx );
}

#endif /* MBEDCRYPTO_ECDSA_C */
