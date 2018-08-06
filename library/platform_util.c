/*
 * Common and shared functions used by multiple modules in the Mbed Crypto
 * library.
 *
 *  Copyright (C) 2018, Arm Limited, All Rights Reserved
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

#include "mbedcrypto/platform_util.h"

#include <stddef.h>
#include <string.h>

#if !defined(MBEDCRYPTO_PLATFORM_ZEROIZE_ALT)
/*
 * This implementation should never be optimized out by the compiler
 *
 * This implementation for mbedcrypto_platform_zeroize() was inspired from Colin
 * Percival's blog article at:
 *
 * http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
 *
 * It uses a volatile function pointer to the standard memset(). Because the
 * pointer is volatile the compiler expects it to change at
 * any time and will not optimize out the call that could potentially perform
 * other operations on the input buffer instead of just setting it to 0.
 * Nevertheless, as pointed out by davidtgoldblatt on Hacker News
 * (refer to http://www.daemonology.net/blog/2014-09-05-erratum.html for
 * details), optimizations of the following form are still possible:
 *
 * if( memset_func != memset )
 *     memset_func( buf, 0, len );
 *
 * Note that it is extremely difficult to guarantee that
 * mbedcrypto_platform_zeroize() will not be optimized out by aggressive compilers
 * in a portable way. For this reason, Mbed Crypto also provides the configuration
 * option MBEDCRYPTO_PLATFORM_ZEROIZE_ALT, which allows users to configure
 * mbedcrypto_platform_zeroize() to use a suitable implementation for their
 * platform and needs.
 */
static void * (* const volatile memset_func)( void *, int, size_t ) = memset;

void mbedcrypto_platform_zeroize( void *buf, size_t len )
{
    memset_func( buf, 0, len );
}
#endif /* MBEDCRYPTO_PLATFORM_ZEROIZE_ALT */
