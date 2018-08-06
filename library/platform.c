/*
 *  Platform abstraction layer
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

#if defined(MBEDCRYPTO_PLATFORM_C)

#include "mbedcrypto/platform.h"
#include "mbedcrypto/platform_util.h"

#if defined(MBEDCRYPTO_PLATFORM_MEMORY)
#if !defined(MBEDCRYPTO_PLATFORM_STD_CALLOC)
static void *platform_calloc_uninit( size_t n, size_t size )
{
    ((void) n);
    ((void) size);
    return( NULL );
}

#define MBEDCRYPTO_PLATFORM_STD_CALLOC   platform_calloc_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_CALLOC */

#if !defined(MBEDCRYPTO_PLATFORM_STD_FREE)
static void platform_free_uninit( void *ptr )
{
    ((void) ptr);
}

#define MBEDCRYPTO_PLATFORM_STD_FREE     platform_free_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_FREE */

void * (*mbedcrypto_calloc)( size_t, size_t ) = MBEDCRYPTO_PLATFORM_STD_CALLOC;
void (*mbedcrypto_free)( void * )     = MBEDCRYPTO_PLATFORM_STD_FREE;

int mbedcrypto_platform_set_calloc_free( void * (*calloc_func)( size_t, size_t ),
                              void (*free_func)( void * ) )
{
    mbedcrypto_calloc = calloc_func;
    mbedcrypto_free = free_func;
    return( 0 );
}
#endif /* MBEDCRYPTO_PLATFORM_MEMORY */

#if defined(_WIN32)
#include <stdarg.h>
int mbedcrypto_platform_win32_snprintf( char *s, size_t n, const char *fmt, ... )
{
    int ret;
    va_list argp;

    /* Avoid calling the invalid parameter handler by checking ourselves */
    if( s == NULL || n == 0 || fmt == NULL )
        return( -1 );

    va_start( argp, fmt );
#if defined(_TRUNCATE) && !defined(__MINGW32__)
    ret = _vsnprintf_s( s, n, _TRUNCATE, fmt, argp );
#else
    ret = _vsnprintf( s, n, fmt, argp );
    if( ret < 0 || (size_t) ret == n )
    {
        s[n-1] = '\0';
        ret = -1;
    }
#endif
    va_end( argp );

    return( ret );
}
#endif

#if defined(MBEDCRYPTO_PLATFORM_SNPRINTF_ALT)
#if !defined(MBEDCRYPTO_PLATFORM_STD_SNPRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_snprintf_uninit( char * s, size_t n,
                                     const char * format, ... )
{
    ((void) s);
    ((void) n);
    ((void) format);
    return( 0 );
}

#define MBEDCRYPTO_PLATFORM_STD_SNPRINTF    platform_snprintf_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_SNPRINTF */

int (*mbedcrypto_snprintf)( char * s, size_t n,
                          const char * format,
                          ... ) = MBEDCRYPTO_PLATFORM_STD_SNPRINTF;

int mbedcrypto_platform_set_snprintf( int (*snprintf_func)( char * s, size_t n,
                                                 const char * format,
                                                 ... ) )
{
    mbedcrypto_snprintf = snprintf_func;
    return( 0 );
}
#endif /* MBEDCRYPTO_PLATFORM_SNPRINTF_ALT */

#if defined(MBEDCRYPTO_PLATFORM_PRINTF_ALT)
#if !defined(MBEDCRYPTO_PLATFORM_STD_PRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_printf_uninit( const char *format, ... )
{
    ((void) format);
    return( 0 );
}

#define MBEDCRYPTO_PLATFORM_STD_PRINTF    platform_printf_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_PRINTF */

int (*mbedcrypto_printf)( const char *, ... ) = MBEDCRYPTO_PLATFORM_STD_PRINTF;

int mbedcrypto_platform_set_printf( int (*printf_func)( const char *, ... ) )
{
    mbedcrypto_printf = printf_func;
    return( 0 );
}
#endif /* MBEDCRYPTO_PLATFORM_PRINTF_ALT */

#if defined(MBEDCRYPTO_PLATFORM_FPRINTF_ALT)
#if !defined(MBEDCRYPTO_PLATFORM_STD_FPRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_fprintf_uninit( FILE *stream, const char *format, ... )
{
    ((void) stream);
    ((void) format);
    return( 0 );
}

#define MBEDCRYPTO_PLATFORM_STD_FPRINTF   platform_fprintf_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_FPRINTF */

int (*mbedcrypto_fprintf)( FILE *, const char *, ... ) =
                                        MBEDCRYPTO_PLATFORM_STD_FPRINTF;

int mbedcrypto_platform_set_fprintf( int (*fprintf_func)( FILE *, const char *, ... ) )
{
    mbedcrypto_fprintf = fprintf_func;
    return( 0 );
}
#endif /* MBEDCRYPTO_PLATFORM_FPRINTF_ALT */

#if defined(MBEDCRYPTO_PLATFORM_EXIT_ALT)
#if !defined(MBEDCRYPTO_PLATFORM_STD_EXIT)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static void platform_exit_uninit( int status )
{
    ((void) status);
}

#define MBEDCRYPTO_PLATFORM_STD_EXIT   platform_exit_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_EXIT */

void (*mbedcrypto_exit)( int status ) = MBEDCRYPTO_PLATFORM_STD_EXIT;

int mbedcrypto_platform_set_exit( void (*exit_func)( int status ) )
{
    mbedcrypto_exit = exit_func;
    return( 0 );
}
#endif /* MBEDCRYPTO_PLATFORM_EXIT_ALT */

#if defined(MBEDCRYPTO_HAVE_TIME)

#if defined(MBEDCRYPTO_PLATFORM_TIME_ALT)
#if !defined(MBEDCRYPTO_PLATFORM_STD_TIME)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static mbedcrypto_time_t platform_time_uninit( mbedcrypto_time_t* timer )
{
    ((void) timer);
    return( 0 );
}

#define MBEDCRYPTO_PLATFORM_STD_TIME   platform_time_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_TIME */

mbedcrypto_time_t (*mbedcrypto_time)( mbedcrypto_time_t* timer ) = MBEDCRYPTO_PLATFORM_STD_TIME;

int mbedcrypto_platform_set_time( mbedcrypto_time_t (*time_func)( mbedcrypto_time_t* timer ) )
{
    mbedcrypto_time = time_func;
    return( 0 );
}
#endif /* MBEDCRYPTO_PLATFORM_TIME_ALT */

#endif /* MBEDCRYPTO_HAVE_TIME */

#if defined(MBEDCRYPTO_ENTROPY_NV_SEED)
#if !defined(MBEDCRYPTO_PLATFORM_NO_STD_FUNCTIONS) && defined(MBEDCRYPTO_FS_IO)
/* Default implementations for the platform independent seed functions use
 * standard libc file functions to read from and write to a pre-defined filename
 */
int mbedcrypto_platform_std_nv_seed_read( unsigned char *buf, size_t buf_len )
{
    FILE *file;
    size_t n;

    if( ( file = fopen( MBEDCRYPTO_PLATFORM_STD_NV_SEED_FILE, "rb" ) ) == NULL )
        return( -1 );

    if( ( n = fread( buf, 1, buf_len, file ) ) != buf_len )
    {
        fclose( file );
        mbedcrypto_platform_zeroize( buf, buf_len );
        return( -1 );
    }

    fclose( file );
    return( (int)n );
}

int mbedcrypto_platform_std_nv_seed_write( unsigned char *buf, size_t buf_len )
{
    FILE *file;
    size_t n;

    if( ( file = fopen( MBEDCRYPTO_PLATFORM_STD_NV_SEED_FILE, "w" ) ) == NULL )
        return -1;

    if( ( n = fwrite( buf, 1, buf_len, file ) ) != buf_len )
    {
        fclose( file );
        return -1;
    }

    fclose( file );
    return( (int)n );
}
#endif /* MBEDCRYPTO_PLATFORM_NO_STD_FUNCTIONS */

#if defined(MBEDCRYPTO_PLATFORM_NV_SEED_ALT)
#if !defined(MBEDCRYPTO_PLATFORM_STD_NV_SEED_READ)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_nv_seed_read_uninit( unsigned char *buf, size_t buf_len )
{
    ((void) buf);
    ((void) buf_len);
    return( -1 );
}

#define MBEDCRYPTO_PLATFORM_STD_NV_SEED_READ   platform_nv_seed_read_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_NV_SEED_READ */

#if !defined(MBEDCRYPTO_PLATFORM_STD_NV_SEED_WRITE)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_nv_seed_write_uninit( unsigned char *buf, size_t buf_len )
{
    ((void) buf);
    ((void) buf_len);
    return( -1 );
}

#define MBEDCRYPTO_PLATFORM_STD_NV_SEED_WRITE   platform_nv_seed_write_uninit
#endif /* !MBEDCRYPTO_PLATFORM_STD_NV_SEED_WRITE */

int (*mbedcrypto_nv_seed_read)( unsigned char *buf, size_t buf_len ) =
            MBEDCRYPTO_PLATFORM_STD_NV_SEED_READ;
int (*mbedcrypto_nv_seed_write)( unsigned char *buf, size_t buf_len ) =
            MBEDCRYPTO_PLATFORM_STD_NV_SEED_WRITE;

int mbedcrypto_platform_set_nv_seed(
        int (*nv_seed_read_func)( unsigned char *buf, size_t buf_len ),
        int (*nv_seed_write_func)( unsigned char *buf, size_t buf_len ) )
{
    mbedcrypto_nv_seed_read = nv_seed_read_func;
    mbedcrypto_nv_seed_write = nv_seed_write_func;
    return( 0 );
}
#endif /* MBEDCRYPTO_PLATFORM_NV_SEED_ALT */
#endif /* MBEDCRYPTO_ENTROPY_NV_SEED */

#if !defined(MBEDCRYPTO_PLATFORM_SETUP_TEARDOWN_ALT)
/*
 * Placeholder platform setup that does nothing by default
 */
int mbedcrypto_platform_setup( mbedcrypto_platform_context *ctx )
{
    (void)ctx;

    return( 0 );
}

/*
 * Placeholder platform teardown that does nothing by default
 */
void mbedcrypto_platform_teardown( mbedcrypto_platform_context *ctx )
{
    (void)ctx;
}
#endif /* MBEDCRYPTO_PLATFORM_SETUP_TEARDOWN_ALT */

#endif /* MBEDCRYPTO_PLATFORM_C */
