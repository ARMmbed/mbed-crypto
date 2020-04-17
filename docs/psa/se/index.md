# PSA secure element driver interface

The secure element driver interface lets you write drivers for external cryptoprocessors such as secure elements (SE), smart cards and hardware security modules (HSM) that perform operations on keys that never leave the external processor and are accessed only through opaque handles.
You can plug such drivers into any implementation of the [PSA Cryptography API](../#application-programming-interface).

**Status: draft** — major changes are still likely.

**Documentation**: for now, please see the header file:
[`include/psa/crypto_se_driver.h`](https://github.com/ARMmbed/mbedtls/blob/development/include/psa/crypto_se_driver.h)

**Mbed TLS support status**: Partial. Only a few operations are supported: key pair generation, import, export and destruction; signature and verification.

**Example**: You can see the code of an [example driver](https://github.com/ARMmbed/mbed-os-atecc608a) for the [Microchip ATECC608A secure element](https://www.microchip.com/wwwproducts/en/ATECC608A).
See the instructions for the [example application using this driver](https://github.com/ARMmbed/mbed-os-example-atecc608a) for how to build [Mbed OS](https://github.com/ARMmbed/mbed-os) with this driver.
