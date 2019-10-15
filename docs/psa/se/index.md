# PSA secure element driver interface

The accelerator interface lets you drivers for external cryptoprocessors into an implementation of the [PSA Cryptography API](../#application-programming-interface). External cryptoprocessors such as secure elements and smart cards perform cryptographic operations with keys accessed via opaque handles.

**Status: draft** — major changes are still likely.

**Documentation**: for now, please see the header file:
[`include/psa/crypto_se_driver.h`](https://github.com/ARMmbed/mbed-crypto/blob/development/include/psa/crypto_se_driver.h)
