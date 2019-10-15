# PSA secure element driver interface

The accelerator interface lets you drivers for external cryptoprocessors into an implementation of the [PSA Cryptography API](../#application-programming-interface). External cryptoprocessors such as secure elements and smart cards perform cryptographic operations with keys accessed via opaque handles.

**Status: draft** — major changes are still likely.

**Documentation**: for now, please see the header file:
[`include/psa/crypto_se_driver.h`](https://github.com/ARMmbed/mbed-crypto/blob/development/include/psa/crypto_se_driver.h)

**Example**: You can see the code of an [example driver](https://github.com/ARMmbed/mbed-os-atecc608a) for the [Microchip ATECC608A secure element](https://www.microchip.com/wwwproducts/en/ATECC608A).
See the instructions for the [example application using this driver](https://github.com/ARMmbed/mbed-os-example-atecc608a) for how to build [Mbed OS](https://github.com/ARMmbed/mbed-os) with this driver.
