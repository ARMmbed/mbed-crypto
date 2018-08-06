/*
 *  An implementation of the ARCFOUR algorithm
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
 *  The ARCFOUR algorithm was publicly disclosed on 94/09.
 *
 *  http://groups.google.com/group/sci.crypt/msg/10a300c9d21afca0
 */

#if !defined(MBEDCRYPTO_CONFIG_FILE)
#include "mbedcrypto/config.h"
#else
#include MBEDCRYPTO_CONFIG_FILE
#endif

#if defined(MBEDCRYPTO_ARC4_C)

#include "mbedcrypto/arc4.h"
#include "mbedcrypto/platform_util.h"

#include <string.h>

#if defined(MBEDCRYPTO_SELF_TEST)
#if defined(MBEDCRYPTO_PLATFORM_C)
#include "mbedcrypto/platform.h"
#else
#include <stdio.h>
#define mbedcrypto_printf printf
#endif /* MBEDCRYPTO_PLATFORM_C */
#endif /* MBEDCRYPTO_SELF_TEST */

#if !defined(MBEDCRYPTO_ARC4_ALT)

void mbedcrypto_arc4_init( mbedcrypto_arc4_context *ctx )
{
    memset( ctx, 0, sizeof( mbedcrypto_arc4_context ) );
}

void mbedcrypto_arc4_free( mbedcrypto_arc4_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedcrypto_platform_zeroize( ctx, sizeof( mbedcrypto_arc4_context ) );
}

/*
 * ARC4 key schedule
 */
void mbedcrypto_arc4_setup( mbedcrypto_arc4_context *ctx, const unsigned char *key,
                 unsigned int keylen )
{
    int i, j, a;
    unsigned int k;
    unsigned char *m;

    ctx->x = 0;
    ctx->y = 0;
    m = ctx->m;

    for( i = 0; i < 256; i++ )
        m[i] = (unsigned char) i;

    j = k = 0;

    for( i = 0; i < 256; i++, k++ )
    {
        if( k >= keylen ) k = 0;

        a = m[i];
        j = ( j + a + key[k] ) & 0xFF;
        m[i] = m[j];
        m[j] = (unsigned char) a;
    }
}

/*
 * ARC4 cipher function
 */
int mbedcrypto_arc4_crypt( mbedcrypto_arc4_context *ctx, size_t length, const unsigned char *input,
                unsigned char *output )
{
    int x, y, a, b;
    size_t i;
    unsigned char *m;

    x = ctx->x;
    y = ctx->y;
    m = ctx->m;

    for( i = 0; i < length; i++ )
    {
        x = ( x + 1 ) & 0xFF; a = m[x];
        y = ( y + a ) & 0xFF; b = m[y];

        m[x] = (unsigned char) b;
        m[y] = (unsigned char) a;

        output[i] = (unsigned char)
            ( input[i] ^ m[(unsigned char)( a + b )] );
    }

    ctx->x = x;
    ctx->y = y;

    return( 0 );
}

#endif /* !MBEDCRYPTO_ARC4_ALT */

#if defined(MBEDCRYPTO_SELF_TEST)
/*
 * ARC4 tests vectors as posted by Eric Rescorla in sep. 1994:
 *
 * http://groups.google.com/group/comp.security.misc/msg/10a300c9d21afca0
 */
static const unsigned char arc4_test_key[3][8] =
{
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static const unsigned char arc4_test_pt[3][8] =
{
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static const unsigned char arc4_test_ct[3][8] =
{
    { 0x75, 0xB7, 0x87, 0x80, 0x99, 0xE0, 0xC5, 0x96 },
    { 0x74, 0x94, 0xC2, 0xE7, 0x10, 0x4B, 0x08, 0x79 },
    { 0xDE, 0x18, 0x89, 0x41, 0xA3, 0x37, 0x5D, 0x3A }
};

/*
 * Checkup routine
 */
int mbedcrypto_arc4_self_test( int verbose )
{
    int i, ret = 0;
    unsigned char ibuf[8];
    unsigned char obuf[8];
    mbedcrypto_arc4_context ctx;

    mbedcrypto_arc4_init( &ctx );

    for( i = 0; i < 3; i++ )
    {
        if( verbose != 0 )
            mbedcrypto_printf( "  ARC4 test #%d: ", i + 1 );

        memcpy( ibuf, arc4_test_pt[i], 8 );

        mbedcrypto_arc4_setup( &ctx, arc4_test_key[i], 8 );
        mbedcrypto_arc4_crypt( &ctx, 8, ibuf, obuf );

        if( memcmp( obuf, arc4_test_ct[i], 8 ) != 0 )
        {
            if( verbose != 0 )
                mbedcrypto_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedcrypto_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedcrypto_printf( "\n" );

exit:
    mbedcrypto_arc4_free( &ctx );

    return( ret );
}

#endif /* MBEDCRYPTO_SELF_TEST */

#endif /* MBEDCRYPTO_ARC4_C */
