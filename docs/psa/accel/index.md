# PSA cryptographic accelerator interface

The accelerator interface lets you drivers for cryptographic accelerators into an implementation of the [PSA Cryptography API](../#application-programming-interface). Cryptographic accelerators perform cryptographic operations with keys in clear text.

**Status: draft** — major changes are still likely.

**Documentation**: for now, please see the header file:
[`include/psa/crypto_accel_driver.h`](https://github.com/ARMmbed/mbed-crypto/blob/development/include/psa/crypto_accel_driver.h)

**Mbed Crypto support status**: Not implemented yet. For now, accelerators use the [Mbed TLS alternative cryptography engine interface](https://tls.mbed.org/kb/development/hw_acc_guidelines).
