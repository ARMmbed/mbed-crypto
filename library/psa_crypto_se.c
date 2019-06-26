/*
 *  PSA crypto support for secure element drivers
 */
/*  Copyright (C) 2019, ARM Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "psa/crypto_se_driver.h"

#include "psa_crypto_se.h"

#include "mbedtls/platform.h"
#if !defined(MBEDTLS_PLATFORM_C)
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif



/****************************************************************/
/* Driver lookup */
/****************************************************************/

typedef struct psa_se_drv_table_entry_s
{
    psa_key_lifetime_t lifetime;
    const psa_drv_se_t *methods;
    psa_drv_se_slot_usage_t *slot_usage;
} psa_se_drv_table_entry_t;

static psa_se_drv_table_entry_t driver_table[PSA_MAX_SE_DRIVERS];

const psa_se_drv_table_entry_t *psa_get_se_driver_entry(
    psa_key_lifetime_t lifetime )
{
    size_t i;
    if( lifetime == 0 )
        return( NULL );
    for( i = 0; i < PSA_MAX_SE_DRIVERS; i++ )
    {
        if( driver_table[i].lifetime == lifetime )
            return( &driver_table[i] );
    }
    return( NULL );
}

const psa_drv_se_t *psa_get_se_driver_methods(
    const psa_se_drv_table_entry_t *drv )
{
    return( drv->methods );
}

const psa_drv_se_t *psa_get_se_driver( psa_key_lifetime_t lifetime )
{
    const psa_se_drv_table_entry_t *drv = psa_get_se_driver_entry( lifetime );
    if( drv == NULL )
        return( NULL );
    else
        return( drv->methods );
}



/****************************************************************/
/* Slot management */
/****************************************************************/

/** The type of bit vector elements. A bit vector is represented as an
 * array of bit vector elements. */
typedef unsigned bv_element_t;
/* Number of bits per bit vector elements. Assumes no padding bits,
 * which Mbed TLS checks in selftest.c. */
#define BV_BITS_PER_ELEMENT ( sizeof( bv_element_t ) * CHAR_BIT )

struct psa_drv_se_slot_usage_s
{
    size_t size; /** Number of elements of \c vector */
    bv_element_t vector[1]; /* Should be vector[] but we don't allow C99 */
};

static psa_key_slot_number_t su_size(
    const psa_drv_se_slot_usage_t *slot_usage )
{
    return( slot_usage->size * BV_BITS_PER_ELEMENT );
}

static int su_get( const psa_drv_se_slot_usage_t *slot_usage,
                   psa_key_slot_number_t n )
{
    bv_element_t elt = slot_usage->vector[n / BV_BITS_PER_ELEMENT];
    return( elt >> (n % BV_BITS_PER_ELEMENT) & 1 );
}

static void su_set( psa_drv_se_slot_usage_t *slot_usage,
                    psa_key_slot_number_t n,
                    int value )
{
    bv_element_t *elt = &slot_usage->vector[n / BV_BITS_PER_ELEMENT];
    bv_element_t mask = 1 << (n % BV_BITS_PER_ELEMENT);
    if( value )
        *elt = *elt | mask;
    else
        *elt = *elt & ~mask;
}

/* Callback function for drivers */
psa_status_t psa_drv_cb_find_free_slot(
    const psa_drv_se_slot_usage_t *slot_usage,
    psa_key_slot_number_t from,
    psa_key_slot_number_t before,
    psa_key_slot_number_t *found )
{
    psa_key_slot_number_t n;
    if( from >= su_size( slot_usage ) )
        return( PSA_ERROR_INSUFFICIENT_STORAGE );
    if( before > su_size( slot_usage ) )
        before = su_size( slot_usage );
    for( n = from; n < before; n++ )
    {
        if( ! su_get( slot_usage, n ) )
        {
            *found = n;
            return( PSA_SUCCESS );
        }
    }
    return( PSA_ERROR_INSUFFICIENT_STORAGE );
}

static psa_status_t load_slot_usage( psa_se_drv_table_entry_t *drv )
{
    size_t n_elements = ( drv->methods->key_management->slot_count +
                          BV_BITS_PER_ELEMENT - 1 ) / BV_BITS_PER_ELEMENT;
    size_t size = ( sizeof( *drv->slot_usage )
                    - sizeof( drv->slot_usage->vector )
                    + sizeof( drv->slot_usage->vector[0] ) * n_elements );
    drv->slot_usage = mbedtls_calloc( 1, size );
    if( drv->slot_usage == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    drv->slot_usage->size = drv->methods->key_management->slot_count;

    /* TOnogrepDO: load */

    return( PSA_SUCCESS );
}

psa_status_t psa_find_se_slot_for_key(
    const psa_key_attributes_t *attributes,
    const psa_se_drv_table_entry_t *drv,
    psa_key_slot_number_t *slot_number )
{
    psa_status_t status;

    /* The maximum possible value of the type is never a valid slot number
     * because it's too large. (0 is valid.) */
    *slot_number = -1;

    if( drv->lifetime != attributes->lifetime )
        return( PSA_ERROR_CORRUPTION_DETECTED );

    /* If the driver doesn't support key creation in any way, give up now. */
    if( drv->methods->key_management == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( drv->methods->key_management->p_allocate == NULL )
    {
        status = psa_drv_cb_find_free_slot(
            drv->slot_usage,
            0, drv->methods->key_management->slot_count,
            slot_number );
    }
    else
    {
        status = drv->methods->key_management->p_allocate( attributes,
                                                           drv->slot_usage,
                                                           slot_number );
    }
    return( status );
}

psa_status_t psa_update_se_slot_usage(
    const psa_se_drv_table_entry_t *drv,
    psa_key_slot_number_t slot_number,
    int value )
{
    su_set( drv->slot_usage, slot_number, value );

    /* TOnogrepDO: save */

    return( PSA_SUCCESS );
}



/****************************************************************/
/* Driver registration */
/****************************************************************/

psa_status_t psa_register_se_driver(
    psa_key_lifetime_t lifetime,
    const psa_drv_se_t *methods)
{
    size_t i;

    if( methods->hal_version != PSA_DRV_SE_HAL_VERSION )
        return( PSA_ERROR_NOT_SUPPORTED );
    /* Driver table entries are 0-initialized. 0 is not a valid driver
     * lifetime because it means a volatile key. */
#if defined(static_assert)
    static_assert( PSA_KEY_LIFETIME_VOLATILE == 0,
                   "Secure element support requires 0 to mean a volatile key" );
#endif
    if( lifetime == PSA_KEY_LIFETIME_VOLATILE ||
        lifetime == PSA_KEY_LIFETIME_PERSISTENT )
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    for( i = 0; i < PSA_MAX_SE_DRIVERS; i++ )
    {
        if( driver_table[i].lifetime == 0 )
            break;
        /* Check that lifetime isn't already in use up to the first free
         * entry. Since entries are created in order and never deleted,
         * there can't be a used entry after the first free entry. */
        if( driver_table[i].lifetime == lifetime )
            return( PSA_ERROR_ALREADY_EXISTS );
    }
    if( i == PSA_MAX_SE_DRIVERS )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    driver_table[i].methods = methods;

    if( methods->key_management != NULL )
    {
        psa_status_t status = load_slot_usage( &driver_table[i] );
        if( status != PSA_SUCCESS )
        {
            driver_table[i].methods = NULL;
            return( status );
        }
    }

    driver_table[i].lifetime = lifetime;
    return( PSA_SUCCESS );
}

void psa_unregister_all_se_drivers( void )
{
    size_t i;
    for( i = 0; i < PSA_MAX_SE_DRIVERS; i++ )
    {
        if( driver_table[i].slot_usage != NULL )
            mbedtls_free( driver_table[i].slot_usage );
    }
    memset( driver_table, 0, sizeof( driver_table ) );
}



/****************************************************************/
/* The end */
/****************************************************************/

#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
