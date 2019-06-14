
# Mbed Crypto ChangeLog


## Mbed Crypto 1.1.0 released xxxx-xx-xx

### Security
 * Make `mbedtls_ecdh_get_params` return an error if the second key
   belongs to a different group from the first. Before, if an application
   passed keys that belonged to different group, the first key's data was
   interpreted according to the second group, which could lead to either an
   error or a meaningless output from `mbedtls_ecdh_get_params`. In the latter
   case, this could expose at most 5 bits of the private key.

### Features
 * Keys may allow a second algorithm. Added to support RFC 4492 section 3.2
   `ECDSA_fixed_ECDH`.
 * Add a macro to get the bit size of an elliptic curve,
   `PSA_ECC_CURVE_BITS()`.
 * Add the Any Policy certificate policy oid, as defined in rfc 5280 section
   4.2.1.4.
 * It is now possible to use NIST key wrap mode via the `mbedtls_cipher` API.
   Contributed by Jack Lloyd and Fortanix Inc.
 * Add the Wi-SUN Field Area Network (FAN) device extended key usage.
 * It is now possible to perform RSA PKCS v1.5 signatures with RIPEMD-160
   digest. Contributed by Jack Lloyd and Fortanix Inc.

### API Changes
 * No changes

### New deprecations
 * No changes

### Bugfix
 * Fix private key DER output in the `key_app_writer` example. File contents
   were shifted by one byte, creating an invalid ASN.1 tag. Fixed by Christian
   Walther in [#2239](https://github.com/ARMmbed/mbedtls/pull/2239).
 * Reduce stack usage of hkdf tests. Fixes
   [#2195](https://github.com/ARMmbed/mbedtls/issues/2195).
 * Fix 1-byte buffer overflow in `mbedtls_mpi_write_string()` when used with
   negative inputs. Found by Guido Vranken in
   [#2404](https://github.com/ARMmbed/mbedtls/issues/2404). Credit to OSS-Fuzz.
 * Fix bugs in the AEAD test suite which would be exposed by ciphers which
   either used both encrypt and decrypt key schedules, or which perform
   padding. GCM and CCM were not affected. Fixed by Jack Lloyd.

### Changes
 * Removal of the X.509 and TLS modules from Mbed Crypto, which continue to be
   maintained within Mbed TLS.
 * Removed the Diffie-Hellman examples which implemented a toy protocol
   inspired by TLS DH key exchange. For an example of how to use the DHM
   module, see the code that calls `mbedtls_dhm_xxx` in `ssl_tls.c` and
   `ssl_cli.c` in Mbed TLS.
 * Remove dead code from `bignum.c` in the default configuration. Found by
   Coverity, reported and fixed by Peter Kolbus (Garmin). Fixes
   [#2309](https://github.com/ARMmbed/mbedtls/issues/2309).
 * Add test for minimal value of `MBEDTLS_MPI_WINDOW_SIZE` to `all.sh`.
   Contributed by Peter Kolbus (Garmin).
 * Ensure that unused bits are zero when writing ASN.1 bitstrings when using
   `mbedtls_asn1_write_bitstring()`.
 * Fix issue when writing the named bitstrings in KeyUsage and NsCertType
   extensions in CSRs and CRTs that caused these bitstrings to not be encoded
   correctly as trailing zeroes were not accounted for as unused bits in the
   leading content octet. Fixes [#1610](https://github.com/ARMmbed/mbedtls/issues/1610).
 * Add a new function `mbedtls_asn1_write_named_bitstring()` to write ASN.1
   named bitstring in DER as required by RFC 5280 Appendix B.
 * Fix 1-byte buffer overflow in `mbedtls_mpi_write_string()` when
   used with negative inputs. Found by Guido Vranken in
   [#2404](https://github.com/ARMmbed/mbedtls/issues/2404).
 * Fix false failure in `all.sh` when backup files exist in `include/mbedtls`
   (e.g. config.h.bak). Fixed by Peter Kolbus (Garmin)
   [#2407](https://github.com/ARMmbed/mbedtls/pull/2407).
 * Add test for minimal value of `MBEDTLS_MPI_WINDOW_SIZE` to `all.sh`.
   Contributed by Peter Kolbus (Garmin).


## Mbed Crypto 1.0.0 released 2019-04-01

### Security
 * No changes

### Features
 * Manage keys through handles instead of requiring external key slot
   management.
 * Implement the new function `psa_copy_key()`, allowing copying keys between
   key slots without an export.
 * Implement the function `psa_hash_clone()`, enabling TLS stacks built on PSA
   to use the intermediate result of hash calculations as part of the TLS
   handshake.
 * Simplify the format of RSA and EC keys, removing the `SubjectPublicKeyInfo`
   encoding layer.
 * Support wildcard hash in signature policies. This supports concrete use
   cases which require a different trade-off between safety and flexibility. In
   particular, X.509 makes it impractical to commit a signature key to a
   specific hash mechanism as was previously required.
 * Other changes for compliance with the PSA Crypto API 1.0.0b1.
 * Support 64-bit key IDs when integrated with a PSA Secure Partition Manager
   (SPM).

### API Changes
 * Simplify the EC and RSA public key formats
 * Replace manual key slot allocation with dynamic key slot allocation and key
   handles (affects most PSA Crypto API functions)
 * Add and require initializers for PSA Crypto contexts
 * Align PSA Crypto error codes with other PSA error codes

### New deprecations
 * No changes

### Bugfix
 * No changes

### Changes
 * No changes
