/*
 *  Public Key layer for writing key files and structures
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

#if defined(MBEDCRYPTO_PK_WRITE_C)

#include "mbedcrypto/pk.h"
#include "mbedcrypto/asn1write.h"
#include "mbedcrypto/oid.h"

#include <string.h>

#if defined(MBEDCRYPTO_RSA_C)
#include "mbedcrypto/rsa.h"
#endif
#if defined(MBEDCRYPTO_ECP_C)
#include "mbedcrypto/ecp.h"
#endif
#if defined(MBEDCRYPTO_ECDSA_C)
#include "mbedcrypto/ecdsa.h"
#endif
#if defined(MBEDCRYPTO_PEM_WRITE_C)
#include "mbedcrypto/pem.h"
#endif

#if defined(MBEDCRYPTO_PLATFORM_C)
#include "mbedcrypto/platform.h"
#else
#include <stdlib.h>
#define mbedcrypto_calloc    calloc
#define mbedcrypto_free       free
#endif

#if defined(MBEDCRYPTO_RSA_C)
/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_write_rsa_pubkey( unsigned char **p, unsigned char *start,
                                mbedcrypto_rsa_context *rsa )
{
    int ret;
    size_t len = 0;
    mbedcrypto_mpi T;

    mbedcrypto_mpi_init( &T );

    /* Export E */
    if ( ( ret = mbedcrypto_rsa_export( rsa, NULL, NULL, NULL, NULL, &T ) ) != 0 ||
         ( ret = mbedcrypto_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

    /* Export N */
    if ( ( ret = mbedcrypto_rsa_export( rsa, &T, NULL, NULL, NULL, NULL ) ) != 0 ||
         ( ret = mbedcrypto_asn1_write_mpi( p, start, &T ) ) < 0 )
        goto end_of_export;
    len += ret;

end_of_export:

    mbedcrypto_mpi_free( &T );
    if( ret < 0 )
        return( ret );

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( p, start, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( p, start, MBEDCRYPTO_ASN1_CONSTRUCTED |
                                                 MBEDCRYPTO_ASN1_SEQUENCE ) );

    return( (int) len );
}
#endif /* MBEDCRYPTO_RSA_C */

#if defined(MBEDCRYPTO_ECP_C)
/*
 * EC public key is an EC point
 */
static int pk_write_ec_pubkey( unsigned char **p, unsigned char *start,
                               mbedcrypto_ecp_keypair *ec )
{
    int ret;
    size_t len = 0;
    unsigned char buf[MBEDCRYPTO_ECP_MAX_PT_LEN];

    if( ( ret = mbedcrypto_ecp_point_write_binary( &ec->grp, &ec->Q,
                                        MBEDCRYPTO_ECP_PF_UNCOMPRESSED,
                                        &len, buf, sizeof( buf ) ) ) != 0 )
    {
        return( ret );
    }

    if( *p < start || (size_t)( *p - start ) < len )
        return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

    *p -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}

/*
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 * }
 */
static int pk_write_ec_param( unsigned char **p, unsigned char *start,
                              mbedcrypto_ecp_keypair *ec )
{
    int ret;
    size_t len = 0;
    const char *oid;
    size_t oid_len;

    if( ( ret = mbedcrypto_oid_get_oid_by_ec_grp( ec->grp.id, &oid, &oid_len ) ) != 0 )
        return( ret );

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_oid( p, start, oid, oid_len ) );

    return( (int) len );
}
#endif /* MBEDCRYPTO_ECP_C */

int mbedcrypto_pk_write_pubkey( unsigned char **p, unsigned char *start,
                             const mbedcrypto_pk_context *key )
{
    int ret;
    size_t len = 0;

#if defined(MBEDCRYPTO_RSA_C)
    if( mbedcrypto_pk_get_type( key ) == MBEDCRYPTO_PK_RSA )
        MBEDCRYPTO_ASN1_CHK_ADD( len, pk_write_rsa_pubkey( p, start, mbedcrypto_pk_rsa( *key ) ) );
    else
#endif
#if defined(MBEDCRYPTO_ECP_C)
    if( mbedcrypto_pk_get_type( key ) == MBEDCRYPTO_PK_ECKEY )
        MBEDCRYPTO_ASN1_CHK_ADD( len, pk_write_ec_pubkey( p, start, mbedcrypto_pk_ec( *key ) ) );
    else
#endif
        return( MBEDCRYPTO_ERR_PK_FEATURE_UNAVAILABLE );

    return( (int) len );
}

int mbedcrypto_pk_write_pubkey_der( mbedcrypto_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    const char *oid;

    c = buf + size;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_pk_write_pubkey( &c, buf, key ) );

    if( c - buf < 1 )
        return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( &c, buf, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( &c, buf, MBEDCRYPTO_ASN1_BIT_STRING ) );

    if( ( ret = mbedcrypto_oid_get_oid_by_pk_alg( mbedcrypto_pk_get_type( key ),
                                       &oid, &oid_len ) ) != 0 )
    {
        return( ret );
    }

#if defined(MBEDCRYPTO_ECP_C)
    if( mbedcrypto_pk_get_type( key ) == MBEDCRYPTO_PK_ECKEY )
    {
        MBEDCRYPTO_ASN1_CHK_ADD( par_len, pk_write_ec_param( &c, buf, mbedcrypto_pk_ec( *key ) ) );
    }
#endif

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_algorithm_identifier( &c, buf, oid, oid_len,
                                                        par_len ) );

    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( &c, buf, len ) );
    MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( &c, buf, MBEDCRYPTO_ASN1_CONSTRUCTED |
                                                MBEDCRYPTO_ASN1_SEQUENCE ) );

    return( (int) len );
}

int mbedcrypto_pk_write_key_der( mbedcrypto_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c = buf + size;
    size_t len = 0;

#if defined(MBEDCRYPTO_RSA_C)
    if( mbedcrypto_pk_get_type( key ) == MBEDCRYPTO_PK_RSA )
    {
        mbedcrypto_mpi T; /* Temporary holding the exported parameters */
        mbedcrypto_rsa_context *rsa = mbedcrypto_pk_rsa( *key );

        /*
         * Export the parameters one after another to avoid simultaneous copies.
         */

        mbedcrypto_mpi_init( &T );

        /* Export QP */
        if( ( ret = mbedcrypto_rsa_export_crt( rsa, NULL, NULL, &T ) ) != 0 ||
            ( ret = mbedcrypto_asn1_write_mpi( &c, buf, &T ) ) < 0 )
            goto end_of_export;
        len += ret;

        /* Export DQ */
        if( ( ret = mbedcrypto_rsa_export_crt( rsa, NULL, &T, NULL ) ) != 0 ||
            ( ret = mbedcrypto_asn1_write_mpi( &c, buf, &T ) ) < 0 )
            goto end_of_export;
        len += ret;

        /* Export DP */
        if( ( ret = mbedcrypto_rsa_export_crt( rsa, &T, NULL, NULL ) ) != 0 ||
            ( ret = mbedcrypto_asn1_write_mpi( &c, buf, &T ) ) < 0 )
            goto end_of_export;
        len += ret;

        /* Export Q */
        if ( ( ret = mbedcrypto_rsa_export( rsa, NULL, NULL,
                                         &T, NULL, NULL ) ) != 0 ||
             ( ret = mbedcrypto_asn1_write_mpi( &c, buf, &T ) ) < 0 )
            goto end_of_export;
        len += ret;

        /* Export P */
        if ( ( ret = mbedcrypto_rsa_export( rsa, NULL, &T,
                                         NULL, NULL, NULL ) ) != 0 ||
             ( ret = mbedcrypto_asn1_write_mpi( &c, buf, &T ) ) < 0 )
            goto end_of_export;
        len += ret;

        /* Export D */
        if ( ( ret = mbedcrypto_rsa_export( rsa, NULL, NULL,
                                         NULL, &T, NULL ) ) != 0 ||
             ( ret = mbedcrypto_asn1_write_mpi( &c, buf, &T ) ) < 0 )
            goto end_of_export;
        len += ret;

        /* Export E */
        if ( ( ret = mbedcrypto_rsa_export( rsa, NULL, NULL,
                                         NULL, NULL, &T ) ) != 0 ||
             ( ret = mbedcrypto_asn1_write_mpi( &c, buf, &T ) ) < 0 )
            goto end_of_export;
        len += ret;

        /* Export N */
        if ( ( ret = mbedcrypto_rsa_export( rsa, &T, NULL,
                                         NULL, NULL, NULL ) ) != 0 ||
             ( ret = mbedcrypto_asn1_write_mpi( &c, buf, &T ) ) < 0 )
            goto end_of_export;
        len += ret;

    end_of_export:

        mbedcrypto_mpi_free( &T );
        if( ret < 0 )
            return( ret );

        MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_int( &c, buf, 0 ) );
        MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( &c, buf, len ) );
        MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( &c,
                                               buf, MBEDCRYPTO_ASN1_CONSTRUCTED |
                                               MBEDCRYPTO_ASN1_SEQUENCE ) );
    }
    else
#endif /* MBEDCRYPTO_RSA_C */
#if defined(MBEDCRYPTO_ECP_C)
    if( mbedcrypto_pk_get_type( key ) == MBEDCRYPTO_PK_ECKEY )
    {
        mbedcrypto_ecp_keypair *ec = mbedcrypto_pk_ec( *key );
        size_t pub_len = 0, par_len = 0;

        /*
         * RFC 5915, or SEC1 Appendix C.4
         *
         * ECPrivateKey ::= SEQUENCE {
         *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
         *      privateKey     OCTET STRING,
         *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
         *      publicKey  [1] BIT STRING OPTIONAL
         *    }
         */

        /* publicKey */
        MBEDCRYPTO_ASN1_CHK_ADD( pub_len, pk_write_ec_pubkey( &c, buf, ec ) );

        if( c - buf < 1 )
            return( MBEDCRYPTO_ERR_ASN1_BUF_TOO_SMALL );
        *--c = 0;
        pub_len += 1;

        MBEDCRYPTO_ASN1_CHK_ADD( pub_len, mbedcrypto_asn1_write_len( &c, buf, pub_len ) );
        MBEDCRYPTO_ASN1_CHK_ADD( pub_len, mbedcrypto_asn1_write_tag( &c, buf, MBEDCRYPTO_ASN1_BIT_STRING ) );

        MBEDCRYPTO_ASN1_CHK_ADD( pub_len, mbedcrypto_asn1_write_len( &c, buf, pub_len ) );
        MBEDCRYPTO_ASN1_CHK_ADD( pub_len, mbedcrypto_asn1_write_tag( &c, buf,
                            MBEDCRYPTO_ASN1_CONTEXT_SPECIFIC | MBEDCRYPTO_ASN1_CONSTRUCTED | 1 ) );
        len += pub_len;

        /* parameters */
        MBEDCRYPTO_ASN1_CHK_ADD( par_len, pk_write_ec_param( &c, buf, ec ) );

        MBEDCRYPTO_ASN1_CHK_ADD( par_len, mbedcrypto_asn1_write_len( &c, buf, par_len ) );
        MBEDCRYPTO_ASN1_CHK_ADD( par_len, mbedcrypto_asn1_write_tag( &c, buf,
                            MBEDCRYPTO_ASN1_CONTEXT_SPECIFIC | MBEDCRYPTO_ASN1_CONSTRUCTED | 0 ) );
        len += par_len;

        /* privateKey: write as MPI then fix tag */
        MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_mpi( &c, buf, &ec->d ) );
        *c = MBEDCRYPTO_ASN1_OCTET_STRING;

        /* version */
        MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_int( &c, buf, 1 ) );

        MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_len( &c, buf, len ) );
        MBEDCRYPTO_ASN1_CHK_ADD( len, mbedcrypto_asn1_write_tag( &c, buf, MBEDCRYPTO_ASN1_CONSTRUCTED |
                                                    MBEDCRYPTO_ASN1_SEQUENCE ) );
    }
    else
#endif /* MBEDCRYPTO_ECP_C */
        return( MBEDCRYPTO_ERR_PK_FEATURE_UNAVAILABLE );

    return( (int) len );
}

#if defined(MBEDCRYPTO_PEM_WRITE_C)

#define PEM_BEGIN_PUBLIC_KEY    "-----BEGIN PUBLIC KEY-----\n"
#define PEM_END_PUBLIC_KEY      "-----END PUBLIC KEY-----\n"

#define PEM_BEGIN_PRIVATE_KEY_RSA   "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_RSA     "-----END RSA PRIVATE KEY-----\n"
#define PEM_BEGIN_PRIVATE_KEY_EC    "-----BEGIN EC PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_EC      "-----END EC PRIVATE KEY-----\n"

/*
 * Max sizes of key per types. Shown as tag + len (+ content).
 */

#if defined(MBEDCRYPTO_RSA_C)
/*
 * RSA public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {          1 + 3
 *       algorithm            AlgorithmIdentifier,  1 + 1 (sequence)
 *                                                + 1 + 1 + 9 (rsa oid)
 *                                                + 1 + 1 (params null)
 *       subjectPublicKey     BIT STRING }          1 + 3 + (1 + below)
 *  RSAPublicKey ::= SEQUENCE {                     1 + 3
 *      modulus           INTEGER,  -- n            1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER   -- e            1 + 3 + MPI_MAX + 1
 *  }
 */
#define RSA_PUB_DER_MAX_BYTES   38 + 2 * MBEDCRYPTO_MPI_MAX_SIZE

/*
 * RSA private keys:
 *  RSAPrivateKey ::= SEQUENCE {                    1 + 3
 *      version           Version,                  1 + 1 + 1
 *      modulus           INTEGER,                  1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER,                  1 + 3 + MPI_MAX + 1
 *      privateExponent   INTEGER,                  1 + 3 + MPI_MAX + 1
 *      prime1            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      prime2            INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      exponent1         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      exponent2         INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      coefficient       INTEGER,                  1 + 3 + MPI_MAX / 2 + 1
 *      otherPrimeInfos   OtherPrimeInfos OPTIONAL  0 (not supported)
 *  }
 */
#define MPI_MAX_SIZE_2          MBEDCRYPTO_MPI_MAX_SIZE / 2 + \
                                MBEDCRYPTO_MPI_MAX_SIZE % 2
#define RSA_PRV_DER_MAX_BYTES   47 + 3 * MBEDCRYPTO_MPI_MAX_SIZE \
                                   + 5 * MPI_MAX_SIZE_2

#else /* MBEDCRYPTO_RSA_C */

#define RSA_PUB_DER_MAX_BYTES   0
#define RSA_PRV_DER_MAX_BYTES   0

#endif /* MBEDCRYPTO_RSA_C */

#if defined(MBEDCRYPTO_ECP_C)
/*
 * EC public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {      1 + 2
 *    algorithm         AlgorithmIdentifier,    1 + 1 (sequence)
 *                                            + 1 + 1 + 7 (ec oid)
 *                                            + 1 + 1 + 9 (namedCurve oid)
 *    subjectPublicKey  BIT STRING              1 + 2 + 1               [1]
 *                                            + 1 (point format)        [1]
 *                                            + 2 * ECP_MAX (coords)    [1]
 *  }
 */
#define ECP_PUB_DER_MAX_BYTES   30 + 2 * MBEDCRYPTO_ECP_MAX_BYTES

/*
 * EC private keys:
 * ECPrivateKey ::= SEQUENCE {                  1 + 2
 *      version        INTEGER ,                1 + 1 + 1
 *      privateKey     OCTET STRING,            1 + 1 + ECP_MAX
 *      parameters [0] ECParameters OPTIONAL,   1 + 1 + (1 + 1 + 9)
 *      publicKey  [1] BIT STRING OPTIONAL      1 + 2 + [1] above
 *    }
 */
#define ECP_PRV_DER_MAX_BYTES   29 + 3 * MBEDCRYPTO_ECP_MAX_BYTES

#else /* MBEDCRYPTO_ECP_C */

#define ECP_PUB_DER_MAX_BYTES   0
#define ECP_PRV_DER_MAX_BYTES   0

#endif /* MBEDCRYPTO_ECP_C */

#define PUB_DER_MAX_BYTES   RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                            RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES
#define PRV_DER_MAX_BYTES   RSA_PRV_DER_MAX_BYTES > ECP_PRV_DER_MAX_BYTES ? \
                            RSA_PRV_DER_MAX_BYTES : ECP_PRV_DER_MAX_BYTES

int mbedcrypto_pk_write_pubkey_pem( mbedcrypto_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char output_buf[PUB_DER_MAX_BYTES];
    size_t olen = 0;

    if( ( ret = mbedcrypto_pk_write_pubkey_der( key, output_buf,
                                     sizeof(output_buf) ) ) < 0 )
    {
        return( ret );
    }

    if( ( ret = mbedcrypto_pem_write_buffer( PEM_BEGIN_PUBLIC_KEY, PEM_END_PUBLIC_KEY,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int mbedcrypto_pk_write_key_pem( mbedcrypto_pk_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char output_buf[PRV_DER_MAX_BYTES];
    const char *begin, *end;
    size_t olen = 0;

    if( ( ret = mbedcrypto_pk_write_key_der( key, output_buf, sizeof(output_buf) ) ) < 0 )
        return( ret );

#if defined(MBEDCRYPTO_RSA_C)
    if( mbedcrypto_pk_get_type( key ) == MBEDCRYPTO_PK_RSA )
    {
        begin = PEM_BEGIN_PRIVATE_KEY_RSA;
        end = PEM_END_PRIVATE_KEY_RSA;
    }
    else
#endif
#if defined(MBEDCRYPTO_ECP_C)
    if( mbedcrypto_pk_get_type( key ) == MBEDCRYPTO_PK_ECKEY )
    {
        begin = PEM_BEGIN_PRIVATE_KEY_EC;
        end = PEM_END_PRIVATE_KEY_EC;
    }
    else
#endif
        return( MBEDCRYPTO_ERR_PK_FEATURE_UNAVAILABLE );

    if( ( ret = mbedcrypto_pem_write_buffer( begin, end,
                                  output_buf + sizeof(output_buf) - ret,
                                  ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDCRYPTO_PEM_WRITE_C */

#endif /* MBEDCRYPTO_PK_WRITE_C */
