# PSA cryptography interfaces

This page contains technical information about the cryptography interfaces in the Arm Platform Security Architecture (PSA) and related documents and software.
For more information about the Platform Security Architecture, see [the Arm Developer website](https://developer.arm.com/architectures/security-architectures/platform-security-architecture).

## Application programming interface

The PSA Cryptography API is a C programming interface for applications that wish to store cryptographic keys and use them to perform cryptographic operations.

**Status: beta** — version 1.0.0 beta 3. Minor changes and clarifications are planned before 1.0. Additional features are planned for 1.x releases.

**Reference documentation**:
[HTML](../html/index.html),
[PDF](../PSA_Cryptography_API_Specification.pdf)

**Reference implementation**: [Mbed Crypto](https://github.com/ARMmbed/mbed-crypto)

## Hardware abstraction layer

PSA includes functional specifications describing a hardware abstraction layer covering [cryptographic accelerators](accel/), [secure elements](se/) and [entropy sources](entropy/).

### Accelerator driver interface

The accelerator interface lets you drivers for cryptographic accelerators into an implementation of the PSA Cryptography API. Cryptographic accelerators perform cryptographic operations with keys in clear text.

For more information, see [PSA cryptography accelerator driver interface](accel/).

### Secure element driver interface

The accelerator interface lets you drivers for external cryptoprocessors into an implementation of the PSA Cryptography API. External cryptoprocessors such as secure elements and smart cards perform cryptographic operations with keys accessed via opaque handles.

For more information, see [PSA secure element driver interface](se/).

### Entropy source driver interface

The accelerator interface lets you drivers for entropy sources such as Hardware Random Number Generators (HRNG), also known as True Random Number Generators (TRNG), into an implementation of the PSA Cryptography API.

For more information, see [PSA entropy source driver interface](entropy/).
