# PSA entropy source driver interface

The entropy source driver interface lets you write drivers for Hardware Random Number Generators (HRNG), also known as True Random Number Generators (TRNG).
You can plug such drivers into any implementation of the [PSA Cryptography API](../#application-programming-interface).

**Status: draft** — major changes are still likely.

**Documentation**: for now, please see the header file:
[`include/psa/crypto_entropy_driver.h`](https://github.com/ARMmbed/mbedtls/blob/development/include/psa/crypto_entropy_driver.h)

**Mbed TLS support status**: Not implemented yet. For now, entropy sources use the [Mbed TLS entropy module](https://tls.mbed.org/kb/how-to/add-entropy-sources-to-entropy-pool).
