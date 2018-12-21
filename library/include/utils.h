/**
 * \file utils.h
 *
 * \brief Mbed Crypto internal utilities
 *
 * This file contains the macros and functions useful for the development and
 * testing of Mbed Crypto.
 *
 */
/*
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MC_UTILS_H
#define MC_UTILS_H

/* A compile-time constant with the value 0. If `const_expr` is not a
 * compile-time constant with a nonzero value, cause a compile-time error. */
#define STATIC_ASSERT_EXPR( const_expr )                                \
    ( 0 && sizeof( struct { int STATIC_ASSERT : 1 - 2 * ! ( const_expr ); } ) )

/* A statement that does nothing after its built. If `const_expr` is not a
 * compile-time constant with a nonzero value, cause a compile-time error. */
#define STATIC_ASSERT( const_expr, msg )                                \
    struct STATIC_ASSERT##msg {                                         \
        int STATIC_ASSERT_##msg : 1 - 2 * ! ( const_expr );             \
    }

#endif /* MC_UTILS_H */
