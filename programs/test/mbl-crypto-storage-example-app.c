/*
 *  mbl-crypto-storage-example-app demonstration program
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
 */

/*
 * *** THIS FILE HAS BEEN MACHINE GENERATED ***
 *
 * This file has been machine generated using the script:
 * generate_test_code.py
 *
 * Test file      : ./test_suite_psa_its.c
 *
 * The following files were used to create this file.
 *
 *      Main code file      : suites/main_test.function
 *      Platform code file  : suites/host_test.function
 *      Helper file         : suites/helpers.function
 *      Test suite file     : suites/test_suite_psa_its.function
 *      Test suite data     : suites/test_suite_psa_its.data
 *
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

/*----------------------------------------------------------------------------*/
/* Common helper code */

/*----------------------------------------------------------------------------*/
/* Headers */

#include <stdlib.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
#include <setjmp.h>
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT8 uint8_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <strings.h>
#endif

/* Type for Hex parameters */
typedef struct data_tag
{
    uint8_t *   x;
    uint32_t    len;
} data_t;

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

typedef enum
{
    PARAMFAIL_TESTSTATE_IDLE = 0,           /* No parameter failure call test */
    PARAMFAIL_TESTSTATE_PENDING,            /* Test call to the parameter failure
                                             * is pending */
    PARAMFAIL_TESTSTATE_CALLED              /* The test call to the parameter
                                             * failure function has been made */
} paramfail_test_state_t;


/*----------------------------------------------------------------------------*/
/* Macros */

/**
 * \brief   This macro tests the expression passed to it as a test step or
 *          individual test in a test case.
 *
 *          It allows a library function to return a value and return an error
 *          code that can be tested.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), will be assumed to be a test
 *          failure.
 *
 *          This macro is not suitable for negative parameter validation tests,
 *          as it assumes the test step will not create an error.
 *
 *          Failing the test means:
 *          - Mark this test case as failed.
 *          - Print a message identifying the failure.
 *          - Jump to the \c exit label.
 *
 *          This macro expands to an instruction, not an expression.
 *          It may jump to the \c exit label.
 *
 * \param   TEST    The test expression to be tested.
 */
#define TEST_ASSERT( TEST )                                 \
    do {                                                    \
       if( ! (TEST) )                                       \
       {                                                    \
          test_fail( #TEST, __LINE__, __FILE__ );           \
          goto exit;                                        \
       }                                                    \
    } while( 0 )

/** Evaluate two expressions and fail the test case if they have different
 * values.
 *
 * \param expr1     An expression to evaluate.
 * \param expr2     The expected value of \p expr1. This can be any
 *                  expression, but it is typically a constant.
 */
#define TEST_EQUAL( expr1, expr2 )              \
    TEST_ASSERT( ( expr1 ) == ( expr2 ) )

/** Evaluate an expression and fail the test case if it returns an error.
 *
 * \param expr      The expression to evaluate. This is typically a call
 *                  to a \c psa_xxx function that returns a value of type
 *                  #psa_status_t.
 */
#define PSA_ASSERT( expr ) TEST_EQUAL( ( expr ), PSA_SUCCESS )

/** Allocate memory dynamically and fail the test case if this fails.
 *
 * You must set \p pointer to \c NULL before calling this macro and
 * put `mbedtls_free( pointer )` in the test's cleanup code.
 *
 * If \p length is zero, the resulting \p pointer will be \c NULL.
 * This is usually what we want in tests since API functions are
 * supposed to accept null pointers when a buffer size is zero.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param pointer   An lvalue where the address of the allocated buffer
 *                  will be stored.
 *                  This expression may be evaluated multiple times.
 * \param length    Number of elements to allocate.
 *                  This expression may be evaluated multiple times.
 *
 */
#define ASSERT_ALLOC( pointer, length )                           \
    do                                                            \
    {                                                             \
        TEST_ASSERT( ( pointer ) == NULL );                       \
        if( ( length ) != 0 )                                     \
        {                                                         \
            ( pointer ) = mbedtls_calloc( sizeof( *( pointer ) ), \
                                          ( length ) );           \
            TEST_ASSERT( ( pointer ) != NULL );                   \
        }                                                         \
    }                                                             \
    while( 0 )

/** Compare two buffers and fail the test case if they differ.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param p1        Pointer to the start of the first buffer.
 * \param size1     Size of the first buffer in bytes.
 *                  This expression may be evaluated multiple times.
 * \param p2        Pointer to the start of the second buffer.
 * \param size2     Size of the second buffer in bytes.
 *                  This expression may be evaluated multiple times.
 */
#define ASSERT_COMPARE( p1, size1, p2, size2 )                          \
    do                                                                  \
    {                                                                   \
        TEST_ASSERT( ( size1 ) == ( size2 ) );                          \
        if( ( size1 ) != 0 )                                            \
            TEST_ASSERT( memcmp( ( p1 ), ( p2 ), ( size1 ) ) == 0 );    \
    }                                                                   \
    while( 0 )

#if defined(MBEDTLS_CHECK_PARAMS) && !defined(MBEDTLS_PARAM_FAILED_ALT)
/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It allows a library function to return a value and tests the return
 *          code on return to confirm the given error code was returned.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure, and the test will pass.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function may return an error value or call
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   PARAM_ERROR_VALUE   The expected error code.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM_RET( PARAM_ERR_VALUE, TEST )                     \
    do {                                                                    \
        test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_PENDING;       \
        if( (TEST) != (PARAM_ERR_VALUE) ||                                  \
            test_info.paramfail_test_state != PARAMFAIL_TESTSTATE_CALLED )  \
        {                                                                   \
            test_fail( #TEST, __LINE__, __FILE__ );                         \
            goto exit;                                                      \
        }                                                                   \
   } while( 0 )

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated byt calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function can only return an error by calling
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM( TEST )                                          \
    do {                                                                    \
        memcpy(jmp_tmp, param_fail_jmp, sizeof(jmp_buf));                   \
        if( setjmp( param_fail_jmp ) == 0 )                                 \
        {                                                                   \
            TEST;                                                           \
            test_fail( #TEST, __LINE__, __FILE__ );                         \
            goto exit;                                                      \
        }                                                                   \
        memcpy(param_fail_jmp, jmp_tmp, sizeof(jmp_buf));                   \
    } while( 0 )
#endif /* MBEDTLS_CHECK_PARAMS && !MBEDTLS_PARAM_FAILED_ALT */

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will not fail.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated by calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended to test that functions returning void
 *          accept all of the parameter values they're supposed to accept - eg
 *          that they don't call MBEDTLS_PARAM_FAILED() when a parameter
 *          that's allowed to be NULL happens to be NULL.
 *
 *          Note: for functions that return something other that void,
 *          checking that they accept all the parameters they're supposed to
 *          accept is best done by using TEST_ASSERT() and checking the return
 *          value as well.
 *
 *          Note: this macro is available even when #MBEDTLS_CHECK_PARAMS is
 *          disabled, as it makes sense to check that the functions accept all
 *          legal values even if this option is disabled - only in that case,
 *          the test is more about whether the function segfaults than about
 *          whether it invokes MBEDTLS_PARAM_FAILED().
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_VALID_PARAM( TEST )                                    \
    TEST_ASSERT( ( TEST, 1 ) );

#define assert(a) if( !( a ) )                                      \
{                                                                   \
    mbedtls_fprintf( stderr, "Assertion Failed at %s:%d - %s\n",   \
                             __FILE__, __LINE__, #a );              \
    mbedtls_exit( 1 );                                             \
}

#if defined(__GNUC__)
/* Test if arg and &(arg)[0] have the same type. This is true if arg is
 * an array but not if it's a pointer. */
#define IS_ARRAY_NOT_POINTER( arg )                                     \
    ( ! __builtin_types_compatible_p( __typeof__( arg ),                \
                                      __typeof__( &( arg )[0] ) ) )
#else
/* On platforms where we don't know how to implement this check,
 * omit it. Oh well, a non-portable check is better than nothing. */
#define IS_ARRAY_NOT_POINTER( arg ) 1
#endif

/* A compile-time constant with the value 0. If `const_expr` is not a
 * compile-time constant with a nonzero value, cause a compile-time error. */
#define STATIC_ASSERT_EXPR( const_expr )                                \
    ( 0 && sizeof( struct { int STATIC_ASSERT : 1 - 2 * ! ( const_expr ); } ) )
/* Return the scalar value `value` (possibly promoted). This is a compile-time
 * constant if `value` is. `condition` must be a compile-time constant.
 * If `condition` is false, arrange to cause a compile-time error. */
#define STATIC_ASSERT_THEN_RETURN( condition, value )   \
    ( STATIC_ASSERT_EXPR( condition ) ? 0 : ( value ) )

#define ARRAY_LENGTH_UNSAFE( array )            \
    ( sizeof( array ) / sizeof( *( array ) ) )
/** Return the number of elements of a static or stack array.
 *
 * \param array         A value of array (not pointer) type.
 *
 * \return The number of elements of the array.
 */
#define ARRAY_LENGTH( array )                                           \
    ( STATIC_ASSERT_THEN_RETURN( IS_ARRAY_NOT_POINTER( array ),         \
                                 ARRAY_LENGTH_UNSAFE( array ) ) )

/** Return the smaller of two values.
 *
 * \param x         An integer-valued expression without side effects.
 * \param y         An integer-valued expression without side effects.
 *
 * \return The smaller of \p x and \p y.
 */
#define MIN( x, y ) ( ( x ) < ( y ) ? ( x ) : ( y ) )

/** Return the larger of two values.
 *
 * \param x         An integer-valued expression without side effects.
 * \param y         An integer-valued expression without side effects.
 *
 * \return The larger of \p x and \p y.
 */
#define MAX( x, y ) ( ( x ) > ( y ) ? ( x ) : ( y ) )

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


/*----------------------------------------------------------------------------*/
/* Global variables */

static struct
{
    paramfail_test_state_t paramfail_test_state;
    int failed;
    const char *test;
    const char *filename;
    int line_no;
}
test_info;

#if defined(MBEDTLS_PLATFORM_C)
mbedtls_platform_context platform_ctx;
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
jmp_buf param_fail_jmp;
jmp_buf jmp_tmp;
#endif

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if defined(MBEDTLS_TEST_NULL_ENTROPY) ||             \
    ( !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
      ( !defined(MBEDTLS_NO_PLATFORM_ENTROPY)  ||     \
         defined(MBEDTLS_HAVEGE_C)             ||     \
         defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||     \
         defined(ENTROPY_NV_SEED) ) )
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */

static void test_fail( const char *test, int line_no, const char* filename )
{
    test_info.failed = 1;
    test_info.test = test;
    test_info.line_no = line_no;
    test_info.filename = filename;
}

static int platform_setup()
{
    int ret = 0;
#if defined(MBEDTLS_PLATFORM_C)
    ret = mbedtls_platform_setup( &platform_ctx );
#endif /* MBEDTLS_PLATFORM_C */
    return( ret );
}

static void platform_teardown()
{
#if defined(MBEDTLS_PLATFORM_C)
    mbedtls_platform_teardown( &platform_ctx );
#endif /* MBEDTLS_PLATFORM_C */
}

#if defined(MBEDTLS_CHECK_PARAMS)
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    /* If we are testing the callback function...  */
    if( test_info.paramfail_test_state == PARAMFAIL_TESTSTATE_PENDING )
    {
        test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_CALLED;
    }
    else
    {
        /* ...else we treat this as an error */

        /* Record the location of the failure, but not as a failure yet, in case
         * it was part of the test */
        test_fail( failure_condition, line, file );
        test_info.failed = 0;

        longjmp( param_fail_jmp, 1 );
    }
}
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
static int redirect_output( FILE** out_stream, const char* path )
{
    int stdout_fd = dup( fileno( *out_stream ) );

    if( stdout_fd == -1 )
    {
        return -1;
    }

    fflush( *out_stream );
    fclose( *out_stream );
    *out_stream = fopen( path, "w" );

    if( *out_stream == NULL )
    {
        close( stdout_fd );
        return -1;
    }

    return stdout_fd;
}

static int restore_output( FILE** out_stream, int old_fd )
{
    fflush( *out_stream );
    fclose( *out_stream );

    *out_stream = fdopen( old_fd, "w" );
    if( *out_stream == NULL )
    {
        return -1;
    }

    return 0;
}

static void close_output( FILE* out_stream )
{
    fclose( out_stream );
}
#endif /* __unix__ || __APPLE__ __MACH__ */

static int unhexify( unsigned char *obuf, const char *ibuf )
{
    unsigned char c, c2;
    int len = strlen( ibuf ) / 2;
    assert( strlen( ibuf ) % 2 == 0 ); /* must be even number of bytes */

    while( *ibuf != 0 )
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}


int hexcmp( uint8_t * a, uint8_t * b, uint32_t a_len, uint32_t b_len )
{
    int ret = 0;
    uint32_t i = 0;

    if( a_len != b_len )
        return( -1 );

    for( i = 0; i < a_len; i++ )
    {
        if( a[i] != b[i] )
        {
            ret = -1;
            break;
        }
    }
    return ret;
}




/*----------------------------------------------------------------------------*/
/* Test Suite Code */


#define TEST_SUITE_ACTIVE

#if defined(MBEDTLS_PSA_ITS_FILE_C)
#include "../../library/psa_crypto_its.h"
#else /* Native ITS implementation */
#include "psa/internal_trusted_storage.h"
#endif

/* Internal definitions of the implementation, copied for the sake of
 * some of the tests and of the cleanup code. */
#define PSA_ITS_STORAGE_PREFIX ""
#define PSA_ITS_STORAGE_FILENAME_PATTERN "%08lx%08lx"
#define PSA_ITS_STORAGE_SUFFIX ".psa_its"
#define PSA_ITS_STORAGE_FILENAME_LENGTH         \
    ( sizeof( PSA_ITS_STORAGE_PREFIX ) - 1 + /*prefix without terminating 0*/ \
      16 + /*UID (64-bit number in hex)*/                               \
      sizeof( PSA_ITS_STORAGE_SUFFIX ) - 1 + /*suffix without terminating 0*/ \
      1 /*terminating null byte*/ )
#define PSA_ITS_STORAGE_TEMP \
    PSA_ITS_STORAGE_PREFIX "tempfile" PSA_ITS_STORAGE_SUFFIX
static void psa_its_fill_filename( psa_storage_uid_t uid, char *filename )
{
    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    mbedtls_snprintf( filename, PSA_ITS_STORAGE_FILENAME_LENGTH,
                      "%s" PSA_ITS_STORAGE_FILENAME_PATTERN "%s",
                      PSA_ITS_STORAGE_PREFIX,
                      (unsigned long) ( uid >> 32 ),
                      (unsigned long) ( uid & 0xffffffff ),
                      PSA_ITS_STORAGE_SUFFIX );
}

/* Maximum uid used by the test, recorded so that cleanup() can delete
 * all files. 0xffffffffffffffff is always cleaned up, so it does not
 * need to and should not be taken into account for uid_max. */
static psa_storage_uid_t uid_max = 0;

static void cleanup( void )
{
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    psa_storage_uid_t uid;
    for( uid = 0; uid < uid_max; uid++ )
    {
        psa_its_fill_filename( uid, filename );
        remove( filename );
    }
    psa_its_fill_filename( (psa_storage_uid_t)( -1 ), filename );
    remove( filename );
    remove( PSA_ITS_STORAGE_TEMP );
    uid_max = 0;
}

static psa_status_t psa_its_set_wrap( psa_storage_uid_t uid,
                                      uint32_t data_length,
                                      const void *p_data,
                                      psa_storage_create_flags_t create_flags )
{
    if( uid_max != (psa_storage_uid_t)( -1 ) && uid_max < uid )
        uid_max = uid;
    return( psa_its_set( uid, (size_t) data_length, p_data, create_flags ) );
}

void test_set_get_remove( int uid_arg, int flags_arg, data_t *data )
{
    psa_storage_uid_t uid = uid_arg;
    uint32_t flags = flags_arg;
    struct psa_storage_info_t info;
    unsigned char *buffer = NULL;
    size_t ret_len = 0;

    ASSERT_ALLOC( buffer, data->len );

    PSA_ASSERT( psa_its_set_wrap( uid, data->len, data->x, flags ) );

    PSA_ASSERT( psa_its_get_info( uid, &info ) );
    TEST_ASSERT( info.size == data->len );
    TEST_ASSERT( info.flags == flags );
    PSA_ASSERT( psa_its_get( uid, 0, data->len, buffer, &ret_len ) );
    ASSERT_COMPARE( data->x, data->len, buffer, data->len );

    PSA_ASSERT( psa_its_remove( uid ) );

exit:
    mbedtls_free( buffer );
    cleanup( );
}

void test_set_get_remove_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};

    test_set_get_remove( *( (int *) params[0] ), *( (int *) params[1] ), &data2 );
}
void test_set_overwrite( int uid_arg,
                    int flags1_arg, data_t *data1,
                    int flags2_arg, data_t *data2 )
{
    psa_storage_uid_t uid = uid_arg;
    uint32_t flags1 = flags1_arg;
    uint32_t flags2 = flags2_arg;
    struct psa_storage_info_t info;
    unsigned char *buffer = NULL;
    size_t ret_len = 0;

    ASSERT_ALLOC( buffer, MAX( data1->len, data2->len ) );

    PSA_ASSERT( psa_its_set_wrap( uid, data1->len, data1->x, flags1 ) );
    PSA_ASSERT( psa_its_get_info( uid, &info ) );
    TEST_ASSERT( info.size == data1->len );
    TEST_ASSERT( info.flags == flags1 );
    PSA_ASSERT( psa_its_get( uid, 0, data1->len, buffer, &ret_len ) );
    ASSERT_COMPARE( data1->x, data1->len, buffer, data1->len );

    PSA_ASSERT( psa_its_set_wrap( uid, data2->len, data2->x, flags2 ) );
    PSA_ASSERT( psa_its_get_info( uid, &info ) );
    TEST_ASSERT( info.size == data2->len );
    TEST_ASSERT( info.flags == flags2 );
    ret_len = 0;
    PSA_ASSERT( psa_its_get( uid, 0, data2->len, buffer, &ret_len ) );
    ASSERT_COMPARE( data2->x, data2->len, buffer, data2->len );

    PSA_ASSERT( psa_its_remove( uid ) );

exit:
    mbedtls_free( buffer );
    cleanup( );
}

void test_set_overwrite_wrapper( void ** params )
{
    data_t data2 = {(uint8_t *) params[2], *( (uint32_t *) params[3] )};
    data_t data5 = {(uint8_t *) params[5], *( (uint32_t *) params[6] )};

    test_set_overwrite( *( (int *) params[0] ), *( (int *) params[1] ), &data2, *( (int *) params[4] ), &data5 );
}
void test_set_multiple( int first_id, int count )
{
    psa_storage_uid_t uid0 = first_id;
    psa_storage_uid_t uid;
    char stored[40];
    char retrieved[40];
    size_t ret_len = 0;

    memset( stored, '.', sizeof( stored ) );
    for( uid = uid0; uid < uid0 + count; uid++ )
    {
        mbedtls_snprintf( stored, sizeof( stored ),
                          "Content of file 0x%08lx", (unsigned long) uid );
        PSA_ASSERT( psa_its_set_wrap( uid, sizeof( stored ), stored, 0 ) );
    }

    for( uid = uid0; uid < uid0 + count; uid++ )
    {
        mbedtls_snprintf( stored, sizeof( stored ),
                          "Content of file 0x%08lx", (unsigned long) uid );
        PSA_ASSERT( psa_its_get( uid, 0, sizeof( stored ), retrieved, &ret_len ) );
        ASSERT_COMPARE( retrieved, sizeof( stored ),
                        stored, sizeof( stored ) );
        PSA_ASSERT( psa_its_remove( uid ) );
        TEST_ASSERT( psa_its_get( uid, 0, 0, NULL, NULL ) ==
                     PSA_ERROR_DOES_NOT_EXIST );
    }

exit:
    cleanup( );
}

void test_set_multiple_wrapper( void ** params )
{

    test_set_multiple( *( (int *) params[0] ), *( (int *) params[1] ) );
}
void test_nonexistent( int uid_arg, int create_and_remove )
{
    psa_storage_uid_t uid = uid_arg;
    struct psa_storage_info_t info;

    if( create_and_remove )
    {
        PSA_ASSERT( psa_its_set_wrap( uid, 0, NULL, 0 ) );
        PSA_ASSERT( psa_its_remove( uid ) );
    }

    TEST_ASSERT( psa_its_remove( uid ) == PSA_ERROR_DOES_NOT_EXIST );
    TEST_ASSERT( psa_its_get_info( uid, &info ) ==
                 PSA_ERROR_DOES_NOT_EXIST );
    TEST_ASSERT( psa_its_get( uid, 0, 0, NULL, NULL ) ==
                 PSA_ERROR_DOES_NOT_EXIST );

exit:
    cleanup( );
}

void test_nonexistent_wrapper( void ** params )
{

    test_nonexistent( *( (int *) params[0] ), *( (int *) params[1] ) );
}
void test_get_at( int uid_arg, data_t *data,
             int offset, int length_arg,
             int expected_status )
{
    psa_storage_uid_t uid = uid_arg;
    unsigned char *buffer = NULL;
    psa_status_t status;
    size_t length = length_arg >= 0 ? length_arg : 0;
    unsigned char *trailer;
    size_t i;
    size_t ret_len = 0;

    ASSERT_ALLOC( buffer, length + 16 );
    trailer = buffer + length;
    memset( trailer, '-', 16 );

    PSA_ASSERT( psa_its_set_wrap( uid, data->len, data->x, 0 ) );

    status = psa_its_get( uid, offset, length_arg, buffer, &ret_len );
    TEST_ASSERT( status == (psa_status_t) expected_status );
    if( status == PSA_SUCCESS )
        ASSERT_COMPARE( data->x + offset, length,
                        buffer, length );
    for( i = 0; i < 16; i++ )
        TEST_ASSERT( trailer[i] == '-' );
    PSA_ASSERT( psa_its_remove( uid ) );

exit:
    mbedtls_free( buffer );
    cleanup( );
}

void test_get_at_wrapper( void ** params )
{
    data_t data1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};

    test_get_at( *( (int *) params[0] ), &data1, *( (int *) params[3] ), *( (int *) params[4] ), *( (int *) params[5] ) );
}


/*----------------------------------------------------------------------------*/
/* Test dispatch code */


/**
 * \brief       Evaluates an expression/macro into its literal integer value.
 *              For optimizing space for embedded targets each expression/macro
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and evaluation code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Expression identifier.
 * \param out_value Pointer to int to hold the integer.
 *
 * \return       0 if exp_id is found. 1 otherwise.
 */
int get_expression( int32_t exp_id, int32_t * out_value )
{
    int ret = KEY_VALUE_MAPPING_FOUND;

    (void) exp_id;
    (void) out_value;

    switch( exp_id )
    {

        case 0:
            {
                *out_value = PSA_SUCCESS;
            }
            break;
        case 1:
            {
                *out_value = PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case 2:
            {
                *out_value = -1;
            }
            break;

        default:
           {
                ret = KEY_VALUE_MAPPING_NOT_FOUND;
           }
           break;
    }
    return( ret );
}


/**
 * \brief       Checks if the dependency i.e. the compile flag is set.
 *              For optimizing space for embedded targets each dependency
 *              is identified by a unique identifier instead of string literals.
 *              Identifiers and check code is generated by script:
 *              generate_test_code.py
 *
 * \param exp_id    Dependency identifier.
 *
 * \return       DEPENDENCY_SUPPORTED if set else DEPENDENCY_NOT_SUPPORTED
 */
int dep_check( int dep_id )
{
    int ret = DEPENDENCY_NOT_SUPPORTED;

    (void) dep_id;

    switch( dep_id )
    {

        default:
            break;
    }
    return( ret );
}


/**
 * \brief       Function pointer type for test function wrappers.
 *
 *
 * \param void **   Pointer to void pointers. Represents an array of test
 *                  function parameters.
 *
 * \return       void
 */
typedef void (*TestWrapper_t)( void ** );


/**
 * \brief       Table of test function wrappers. Used by dispatch_test().
 *              This table is populated by script:
 *              generate_test_code.py
 *
 */
TestWrapper_t test_funcs[] =
{
    /* Function Id: 0 */
    test_set_get_remove_wrapper,
    /* Function Id: 1 */
    test_set_overwrite_wrapper,
    /* Function Id: 2 */
    test_set_multiple_wrapper,
    /* Function Id: 3 */
    test_nonexistent_wrapper,
    /* Function Id: 4 */
    test_get_at_wrapper,
};

/**
 * \brief        Execute the test function.
 *
 *               This is a wrapper function around the test function execution
 *               to allow the setjmp() call used to catch any calls to the
 *               parameter failure callback, to be used. Calls to setjmp()
 *               can invalidate the state of any local auto variables.
 *
 * \param fp     Function pointer to the test function
 * \param params Parameters to pass
 *
 */
void execute_function_ptr(TestWrapper_t fp, void **params)
{
#if defined(MBEDTLS_CHECK_PARAMS)
    if ( setjmp( param_fail_jmp ) == 0 )
    {
        fp( params );
    }
    else
    {
        /* Unexpected parameter validation error */
        test_info.failed = 1;
    }

    memset( param_fail_jmp, 0, sizeof(jmp_buf) );
#else
    fp( params );
#endif
}

/**
 * \brief        Dispatches test functions based on function index.
 *
 * \param exp_id    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int dispatch_test( int func_idx, void ** params )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof( test_funcs ) / sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp )
            execute_function_ptr(fp, params);
        else
            ret = DISPATCH_UNSUPPORTED_SUITE;
    }
    else
    {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return( ret );
}


/**
 * \brief       Checks if test function is supported
 *
 * \param exp_id    Test function index.
 *
 * \return       DISPATCH_TEST_SUCCESS if found
 *               DISPATCH_TEST_FN_NOT_FOUND if not found
 *               DISPATCH_UNSUPPORTED_SUITE if not compile time enabled.
 */
int check_test( int func_idx )
{
    int ret = DISPATCH_TEST_SUCCESS;
    TestWrapper_t fp = NULL;

    if ( func_idx < (int)( sizeof(test_funcs)/sizeof( TestWrapper_t ) ) )
    {
        fp = test_funcs[func_idx];
        if ( fp == NULL )
            ret = DISPATCH_UNSUPPORTED_SUITE;
    }
    else
    {
        ret = DISPATCH_TEST_FN_NOT_FOUND;
    }

    return( ret );
}


/**
 * \brief       Verifies that string is in string parameter format i.e. "<str>"
 *              It also strips enclosing '"' from the input string.
 *
 * \param str   String parameter.
 *
 * \return      0 if success else 1
 */
int verify_string( char **str )
{
    if( ( *str )[0] != '"' ||
        ( *str )[strlen( *str ) - 1] != '"' )

    {
        mbedtls_fprintf( stderr,
            "Expected string (with \"\") for parameter and got: %s\n", *str );
        return( -1 );
    }

    ( *str )++;
    ( *str )[strlen( *str ) - 1] = '\0';

    return( 0 );
}

/**
 * \brief       Verifies that string is an integer. Also gives the converted
 *              integer value.
 *
 * \param str   Input string.
 * \param value Pointer to int for output value.
 *
 * \return      0 if success else 1
 */
int verify_int( char *str, int *value )
{
    size_t i;
    int minus = 0;
    int digits = 1;
    int hex = 0;

    for( i = 0; i < strlen( str ); i++ )
    {
        if( i == 0 && str[i] == '-' )
        {
            minus = 1;
            continue;
        }

        if( ( ( minus && i == 2 ) || ( !minus && i == 1 ) ) &&
            str[i - 1] == '0' && ( str[i] == 'x' || str[i] == 'X' ) )
        {
            hex = 1;
            continue;
        }

        if( ! ( ( str[i] >= '0' && str[i] <= '9' ) ||
                ( hex && ( ( str[i] >= 'a' && str[i] <= 'f' ) ||
                           ( str[i] >= 'A' && str[i] <= 'F' ) ) ) ) )
        {
            digits = 0;
            break;
        }
    }

    if( digits )
    {
        if( hex )
            *value = strtol( str, NULL, 16 );
        else
            *value = strtol( str, NULL, 10 );

        return( 0 );
    }

    mbedtls_fprintf( stderr,
                    "Expected integer for parameter and got: %s\n", str );
    return( KEY_VALUE_MAPPING_NOT_FOUND );
}


/**
 * \brief       Usage string.
 *
 */
#define USAGE \
    "Usage: %s [OPTIONS] files...\n\n" \
    "   Command line arguments:\n" \
    "     files...          One or more test data files. If no file is\n" \
    "                       specified the following default test case\n" \
    "                       file is used:\n" \
    "                           %s\n\n" \
    "   Options:\n" \
    "     -v | --verbose    Display full information about each test\n" \
    "     -h | --help       Display this information\n\n", \
    argv[0], \
    "TESTCASE_FILENAME"


/**
 * \brief       Splits string delimited by ':'. Ignores '\:'.
 *
 * \param buf           Input string
 * \param len           Input string length
 * \param params        Out params found
 * \param params_len    Out params array len
 *
 * \return      Count of strings found.
 */
static int parse_arguments( char *buf, size_t len, char **params,
                            size_t params_len )
{
    size_t cnt = 0, i;
    char *cur = buf;
    char *p = buf, *q;

    params[cnt++] = cur;

    while( *p != '\0' && p < ( buf + len ) )
    {
        if( *p == '\\' )
        {
            p++;
            p++;
            continue;
        }
        if( *p == ':' )
        {
            if( p + 1 < buf + len )
            {
                cur = p + 1;
                assert( cnt < params_len );
                params[cnt++] = cur;
            }
            *p = '\0';
        }

        p++;
    }

    /* Replace newlines, question marks and colons in strings */
    for( i = 0; i < cnt; i++ )
    {
        p = params[i];
        q = params[i];

        while( *p != '\0' )
        {
            if( *p == '\\' && *( p + 1 ) == 'n' )
            {
                p += 2;
                *( q++ ) = '\n';
            }
            else if( *p == '\\' && *( p + 1 ) == ':' )
            {
                p += 2;
                *( q++ ) = ':';
            }
            else if( *p == '\\' && *( p + 1 ) == '?' )
            {
                p += 2;
                *( q++ ) = '?';
            }
            else
                *( q++ ) = *( p++ );
        }
        *q = '\0';
    }

    return( cnt );
}

/**
 * \brief       Converts parameters into test function consumable parameters.
 *              Example: Input:  {"int", "0", "char*", "Hello",
 *                                "hex", "abef", "exp", "1"}
 *                      Output:  {
 *                                0,                // Verified int
 *                                "Hello",          // Verified string
 *                                2, { 0xab, 0xef },// Converted len,hex pair
 *                                9600              // Evaluated expression
 *                               }
 *
 *
 * \param cnt               Parameter array count.
 * \param params            Out array of found parameters.
 * \param int_params_store  Memory for storing processed integer parameters.
 *
 * \return      0 for success else 1
 */
static int convert_params( size_t cnt , char ** params , int * int_params_store )
{
    char ** cur = params;
    char ** out = params;
    int ret = DISPATCH_TEST_SUCCESS;

    while ( cur < params + cnt )
    {
        char * type = *cur++;
        char * val = *cur++;

        if ( strcmp( type, "char*" ) == 0 )
        {
            if ( verify_string( &val ) == 0 )
            {
              *out++ = val;
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "int" ) == 0 )
        {
            if ( verify_int( val, int_params_store ) == 0 )
            {
              *out++ = (char *) int_params_store++;
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "hex" ) == 0 )
        {
            if ( verify_string( &val ) == 0 )
            {
                *int_params_store = unhexify( (unsigned char *) val, val );
                *out++ = val;
                *out++ = (char *)(int_params_store++);
            }
            else
            {
                ret = ( DISPATCH_INVALID_TEST_DATA );
                break;
            }
        }
        else if ( strcmp( type, "exp" ) == 0 )
        {
            int exp_id = strtol( val, NULL, 10 );
            if ( get_expression ( exp_id, int_params_store ) == 0 )
            {
              *out++ = (char *)int_params_store++;
            }
            else
            {
              ret = ( DISPATCH_INVALID_TEST_DATA );
              break;
            }
        }
        else
        {
          ret = ( DISPATCH_INVALID_TEST_DATA );
          break;
        }
    }
    return( ret );
}

/**
 * \brief       Tests snprintf implementation with test input.
 *
 * \note
 * At high optimization levels (e.g. gcc -O3), this function may be
 * inlined in run_test_snprintf. This can trigger a spurious warning about
 * potential misuse of snprintf from gcc -Wformat-truncation (observed with
 * gcc 7.2). This warning makes tests in run_test_snprintf redundant on gcc
 * only. They are still valid for other compilers. Avoid this warning by
 * forbidding inlining of this function by gcc.
 *
 * \param n         Buffer test length.
 * \param ref_buf   Expected buffer.
 * \param ref_ret   Expected snprintf return value.
 *
 * \return      0 for success else 1
 */
#if defined(__GNUC__)
__attribute__((__noinline__))
#endif
static int test_snprintf( size_t n, const char ref_buf[10], int ref_ret )
{
    int ret;
    char buf[10] = "xxxxxxxxx";
    const char ref[10] = "xxxxxxxxx";

    if( n >= sizeof( buf ) )
        return( -1 );
    ret = mbedtls_snprintf( buf, n, "%s", "123" );
    if( ret < 0 || (size_t) ret >= n )
        ret = -1;

    if( strncmp( ref_buf, buf, sizeof( buf ) ) != 0 ||
        ref_ret != ret ||
        memcmp( buf + n, ref + n, sizeof( buf ) - n ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

/**
 * \brief       Tests snprintf implementation.
 *
 * \param none
 *
 * \return      0 for success else 1
 */
static int run_test_snprintf( void )
{
    return( test_snprintf( 0, "xxxxxxxxx",  -1 ) != 0 ||
            test_snprintf( 1, "",           -1 ) != 0 ||
            test_snprintf( 2, "1",          -1 ) != 0 ||
            test_snprintf( 3, "12",         -1 ) != 0 ||
            test_snprintf( 4, "123",         3 ) != 0 ||
            test_snprintf( 5, "123",         3 ) != 0 );
}

unsigned int mbl_crypto_storage_test_suite_psa_its_datax_idx = 0;    /**/

/* Array of sample test data string specifications taken from generated file test_suite_psa_its.datax */
const char* mbl_crypto_storage_test_suite_psa_its_datax_str[] = {
    "Set/get/remove 0 bytes",
    "0:int:0:int:0:hex:\"\"",
    "Set/get/remove 1000 bytes",
    "0:int:0:int:0:hex:\"6a07ecfcc7c7bfe0129d56d2dcf2955a12845b9e6e0034b0ed7226764261c6222a07b9f654deb682130eb1cd07ed298324e60a46f9c76c8a5a0be000c69e93dd81054ca21fbc6190cef7745e9d5436f70e20e10cbf111d1d40c9ceb83be108775199d81abaf0fecfe30eaa08e7ed82517cba939de4449f7ac5c730fcbbf56e691640b0129db0e178045dd2034262de9138873d9bdca57685146a3d516ff13c29e6628a00097435a8e10fef7faff62d2963c303a93793e2211d8604556fec08cd59c0f5bd1f22eea64be13e88b3f454781e83fe6e771d3d81eb2fbe2021e276f42a93db5343d767d854115e74f5e129a8036b1e81aced9872709d515e00bcf2098ccdee23006b0e836b27dc8aaf30f53fe58a31a6408abb79b13098c22e262a98040f9b09809a3b43bd42eb01cf1d17bbc8b4dfe51fa6573d4d8741943e3ae71a649e194c1218f2e20556c7d8cfe8c64d8cc1aa94531fbf638768c7d19b3c079299cf4f26ed3f964efb8fd23d82b4157a51f46da11156c74e2d6e2fd788869ebb52429e12a82da2ba083e2e74565026162f29ca22582da72a2698e7c5d958b919bc2cdfe12f50364ccfed30efd5cd120a7d5f196b2bd7f911bb44d5871eb3dedcd70ece7faf464988f9fe361f23d7244b1e08bee921d0f28bdb4912675809d099876d4d15b7d13ece356e1f2a5dce64feb3d6749a07a4f2b7721190e17a9ab2966e48b6d25187070b81eb45b1c44608b2f0e175958ba57fcf1b2cd145eea5fd4de858d157ddac69dfbb5d5d6f0c1691b0fae5a143b6e58cdf5000f28d74b3322670ed11e740c828c7bfad4e2f392012da3ac931ea26ed15fd003e604071f5900c6e1329d021805d50da9f1e732a49bcc292d9f8e07737cfd59442e8d7aaa813b18183a68e22bf6b4519545dd7d2d519db3652be4131bad4f4b0625dbaa749e979f6ee8c1b97803cb50a2fa20dc883eac932a824b777b226e15294de6a80be3ddef41478fe18172d64407a004de6bae18bc60e90c902c1cbb0e1633395b42391f5011be0d480541987609b0cd8d902ea29f86f73e7362340119323eb0ea4f672b70d6e9a9df5235f9f1965f5cb0c2998c5a7f4754e83eeda5d95fefbbaaa0875fe37b7ca461e7281cc5479162627c5a709b45fd9ddcde4dfb40659e1d70fa7361d9fc7de24f9b8b13259423fdae4dbb98d691db687467a5a7eb027a4a0552a03e430ac8a32de0c30160ba60a036d6b9db2d6182193283337b92e7438dc5d6eb4fa00200d8efa9127f1c3a32ac8e202262773aaa5a965c6b8035b2e5706c32a55511560429ddf1df4ac34076b7eedd9cf94b6915a894fdd9084ffe3db0e7040f382c3cd04f0484595de95865c36b6bf20f46a78cdfb37228acbeb218de798b9586f6d99a0cbae47e80d\"",
    "Overwrite 18 -> 3",
    "1:int:0:int:0x12345678:hex:\"404142434445464748494a4b4c4d4e4f5051\":int:0x01020304:hex:\"abcdef\"",
    "Multiple files",
    "2:int:0:int:5",
    "Get 1 byte of 10 at -1: out of range",
    "4:int:0:hex:\"40414243444546474849\":exp:2:int:1:exp:1",
    NULL
};

/**
 * \brief
 *
 * \param f     FILE pointer, ignored
 * \param buf   Pointer to memory to hold read line.
 * \param len   Length of the buf.
 *
 * \return      0 if success else -1
 */
int mbl_crypto_storage_test_suite_psa_its_datax_get_line( char *buf, size_t len )
{
    int ret = -1;

    if( len > 0 && mbl_crypto_storage_test_suite_psa_its_datax_str[mbl_crypto_storage_test_suite_psa_its_datax_idx] != NULL ) {
        memset( buf, 0, len );
        len = MIN( len, strlen( mbl_crypto_storage_test_suite_psa_its_datax_str[mbl_crypto_storage_test_suite_psa_its_datax_idx] ) );
        strncpy( buf, mbl_crypto_storage_test_suite_psa_its_datax_str[mbl_crypto_storage_test_suite_psa_its_datax_idx], len );
        mbl_crypto_storage_test_suite_psa_its_datax_idx++;
        ret = 0;
    }
    return ret;
}

/**
 * \brief       Desktop implementation of execute_tests().
 *              Parses command line and executes tests from
 *              supplied or default data file.
 *
 * \param argc  Command line argument count.
 * \param argv  Argument array.
 *
 * \return      Program exit status.
 */
int execute_tests( int argc , const char ** argv )
{
    /* Local Configurations and options */
    int option_verbose = 0;
    int function_id = 0;

    /* Other Local variables */
    int arg_index = 1;
    const char *next_arg;
    int ret = 0, i, cnt;
    int total_errors = 0, total_tests = 0, total_skipped = 0;
    char buf[5000];
    char *params[50];
    /* Store for proccessed integer params. */
    int int_params[50];
    void *pointer;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    int stdout_fd = -1;
#endif /* __unix__ || __APPLE__ __MACH__ */

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
    unsigned char alloc_buf[1000000];
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof( alloc_buf ) );
#endif
    int unmet_dep_count = 0;
    char *unmet_dependencies[20];

    /*
     * The C standard doesn't guarantee that all-bits-0 is the representation
     * of a NULL pointer. We do however use that in our code for initializing
     * structures, which should work on every modern platform. Let's be sure.
     */
    memset( &pointer, 0, sizeof( void * ) );
    if( pointer != NULL )
    {
        mbedtls_fprintf( stderr, "all-bits-zero is not a NULL pointer\n" );
        return( 1 );
    }

    /*
     * Make sure we have a snprintf that correctly zero-terminates
     */
    if( run_test_snprintf() != 0 )
    {
        mbedtls_fprintf( stderr, "the snprintf implementation is broken\n" );
        return( 1 );
    }

    while( arg_index < argc )
    {
        next_arg = argv[arg_index];

        if( strcmp( next_arg, "--verbose" ) == 0 ||
                 strcmp( next_arg, "-v" ) == 0 )
        {
            option_verbose = 1;
        }
        else if( strcmp(next_arg, "--help" ) == 0 ||
                 strcmp(next_arg, "-h" ) == 0 )
        {
            mbedtls_fprintf( stdout, USAGE );
            mbedtls_exit( EXIT_SUCCESS );
        }

        arg_index++;
    }

    /* Initialize the struct that holds information about the last test */
    memset( &test_info, 0, sizeof( test_info ) );

    /* Now begin to execute the tests*/
    while( ret == 0 )
    {
        if( unmet_dep_count > 0 )
        {
            mbedtls_fprintf( stderr,
                "FATAL: Dep count larger than zero at start of loop\n" );
            mbedtls_exit( MBEDTLS_EXIT_FAILURE );
        }
        unmet_dep_count = 0;

        if( ( ret = mbl_crypto_storage_test_suite_psa_its_datax_get_line( buf, sizeof(buf) ) ) != 0 )
            break;
        mbedtls_fprintf( stdout, "%s%.66s", test_info.failed ? "\n" : "", buf );
        mbedtls_fprintf( stdout, " " );
        for( i = strlen( buf ) + 1; i < 67; i++ )
            mbedtls_fprintf( stdout, "." );
        mbedtls_fprintf( stdout, " " );
        fflush( stdout );

        total_tests++;

        if( ( ret = mbl_crypto_storage_test_suite_psa_its_datax_get_line( buf, sizeof( buf ) ) ) != 0 )
            break;
        cnt = parse_arguments( buf, strlen( buf ), params,
                               sizeof( params ) / sizeof( params[0] ) );

        if( strcmp( params[0], "depends_on" ) == 0 )
        {
            for( i = 1; i < cnt; i++ )
            {
                int dep_id = strtol( params[i], NULL, 10 );
                if( dep_check( dep_id ) != DEPENDENCY_SUPPORTED )
                {
                    if( 0 == option_verbose )
                    {
                        /* Only one count is needed if not verbose */
                        unmet_dep_count++;
                        break;
                    }

                    unmet_dependencies[ unmet_dep_count ] = strdup( params[i] );
                    if(  unmet_dependencies[ unmet_dep_count ] == NULL )
                    {
                        mbedtls_fprintf( stderr, "FATAL: Out of memory\n" );
                        mbedtls_exit( MBEDTLS_EXIT_FAILURE );
                    }
                    unmet_dep_count++;
                }
            }

            if( ( ret = mbl_crypto_storage_test_suite_psa_its_datax_get_line( buf, sizeof( buf ) ) ) != 0 )
                break;
            cnt = parse_arguments( buf, strlen( buf ), params,
                                   sizeof( params ) / sizeof( params[0] ) );
        }

        // If there are no unmet dependencies execute the test
        if( unmet_dep_count == 0 )
        {
            test_info.failed = 0;
            test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_IDLE;

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
            /* Suppress all output from the library unless we're verbose
             * mode
             */
            if( !option_verbose )
            {
                stdout_fd = redirect_output( &stdout, "/dev/null" );
                if( stdout_fd == -1 )
                {
                    /* Redirection has failed with no stdout so exit */
                    exit( 1 );
                }
            }
#endif /* __unix__ || __APPLE__ __MACH__ */

            function_id = strtol( params[0], NULL, 10 );
            if ( (ret = check_test( function_id )) == DISPATCH_TEST_SUCCESS )
            {
                ret = convert_params( cnt - 1, params + 1, int_params );
                if ( DISPATCH_TEST_SUCCESS == ret )
                {
                    ret = dispatch_test( function_id, (void **)( params + 1 ) );
                }
            }

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
            if( !option_verbose && restore_output( &stdout, stdout_fd ) )
            {
                    /* Redirection has failed with no stdout so exit */
                    exit( 1 );
            }
#endif /* __unix__ || __APPLE__ __MACH__ */

        }

        if( unmet_dep_count > 0 || ret == DISPATCH_UNSUPPORTED_SUITE )
        {
            total_skipped++;
            mbedtls_fprintf( stdout, "----" );

            if( 1 == option_verbose && ret == DISPATCH_UNSUPPORTED_SUITE )
            {
                mbedtls_fprintf( stdout, "\n   Test Suite not enabled" );
            }

            if( 1 == option_verbose && unmet_dep_count > 0 )
            {
                mbedtls_fprintf( stdout, "\n   Unmet dependencies: " );
                for( i = 0; i < unmet_dep_count; i++ )
                {
                    mbedtls_fprintf( stdout, "%s  ",
                                    unmet_dependencies[i] );
                    free( unmet_dependencies[i] );
                }
            }
            mbedtls_fprintf( stdout, "\n" );
            fflush( stdout );

            unmet_dep_count = 0;
        }
        else if( ret == DISPATCH_TEST_SUCCESS )
        {
            if( test_info.failed == 0 )
            {
                mbedtls_fprintf( stdout, "PASS\n" );
            }
            else
            {
                total_errors++;
                mbedtls_fprintf( stdout, "FAILED\n" );
                mbedtls_fprintf( stdout, "  %s\n  at line %d, %s\n",
                                 test_info.test, test_info.line_no,
                                 test_info.filename );
            }
            fflush( stdout );
        }
        else if( ret == DISPATCH_INVALID_TEST_DATA )
        {
            mbedtls_fprintf( stderr, "FAILED: FATAL PARSE ERROR\n" );
            mbedtls_exit( 2 );
        }
        else if( ret == DISPATCH_TEST_FN_NOT_FOUND )
        {
            mbedtls_fprintf( stderr, "FAILED: FATAL TEST FUNCTION NOT FUND\n" );
            mbedtls_exit( 2 );
        }
        else
            total_errors++;
        }

    /* In case we encounter early end of file */
    for( i = 0; i < unmet_dep_count; i++ )
        free( unmet_dependencies[i] );

    mbedtls_fprintf( stdout, "\n----------------------------------------------------------------------------\n\n");
    if( total_errors == 0 )
        mbedtls_fprintf( stdout, "PASSED" );
    else
        mbedtls_fprintf( stdout, "FAILED" );

    mbedtls_fprintf( stdout, " (%d / %d tests (%d skipped))\n",
             total_tests - total_errors, total_tests, total_skipped );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && \
    !defined(TEST_SUITE_MEMORY_BUFFER_ALLOC)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    if( stdout_fd != -1 )
        close_output( stdout );
#endif /* __unix__ || __APPLE__ __MACH__ */

    return( total_errors != 0 );
}


/* Main Test code */


/**
 * \brief       Program main. Invokes platform specific execute_tests().
 *
 * \param argc      Command line arguments count.
 * \param argv      Array of command line arguments.
 *
 * \return       Exit code.
 */
int main( int argc, const char *argv[] )
{
    int ret = platform_setup();
    if( ret != 0 )
    {
        mbedtls_fprintf( stderr,
                         "FATAL: Failed to initialize platform - error %d\n",
                         ret );
        return( -1 );
    }

    ret = execute_tests( argc, argv );
    platform_teardown();
    return( ret );
}
