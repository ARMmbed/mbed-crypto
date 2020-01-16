option(INSTALL_MBEDTLS_HEADERS "Install mbed TLS headers." ON)

if(INSTALL_MBEDTLS_HEADERS)

    file(GLOB headers "mbedtls/*.h")
    file(GLOB psa_headers "psa/*.h")

    if(USE_CRYPTO_SUBMODULE)
        # Don't overwrite mbedtls's header files!
        # config.h is supposed to be automatically checked for compatibility
        # in automatic builds, while the other files should not just be
        # compatible, but also identical in theory.
        # Practically, we don't check that in crypto but just assume that the
        # submodule configuration is sane and trust tls's headers.
        list(REMOVE_ITEM headers    "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/compat-1.3.h"
                                    "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/config.h"
                                    "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/error.h"
                                    "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/version.h")
    endif(USE_CRYPTO_SUBMODULE)

    install(FILES ${headers}
        DESTINATION include/mbedtls
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(FILES ${psa_headers}
        DESTINATION include/psa
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

endif(INSTALL_MBEDTLS_HEADERS)

# Make config.h available in an out-of-source build.
if (ENABLE_TESTING AND NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    link_to_source(mbedtls)
    link_to_source(psa)
endif()
