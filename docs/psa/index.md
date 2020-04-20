# PSA cryptography interfaces

This page contains technical information about the cryptography interfaces in the Arm Platform Security Architecture (PSA) and related documents and software.
For more information about the Platform Security Architecture, see [the Arm Developer website](https://developer.arm.com/architectures/security-architectures/platform-security-architecture).

## Application programming interface

The PSA Cryptography API is a C programming interface for applications that wish to store cryptographic keys and use them to perform cryptographic operations.

**Status: beta** — version 1.0.0 beta 3. Minor changes and clarifications are planned before 1.0. Additional features are planned for 1.x releases.

**Reference documentation**:
[HTML](../html/index.html),
[PDF](../PSA_Cryptography_API_Specification.pdf)

**Reference implementation**: [Mbed TLS](https://github.com/ARMmbed/mbed-tls)

## Hardware abstraction layer

PSA includes functional specifications describing a hardware abstraction layer covering [cryptographic accelerators](accel/), [secure elements](se/) and [entropy sources](entropy/).

### Accelerator driver interface

The cryptographic accelerator driver interface lets you write drivers for hardware that performs cryptographic operations with keys in clear text.
You can plug such drivers into any implementation of the PSA Cryptography API.

For more information, see [PSA cryptography accelerator driver interface](accel/).

### Secure element driver interface

The secure element driver interface lets you write drivers for external cryptoprocessors such as secure elements (SE), smart cards and hardware security modules (HSM) that perform operations on keys that never leave the external processor and are accessed only through opaque handles.
You can plug such drivers into any implementation of the PSA Cryptography API.

For more information, see [PSA secure element driver interface](se/).

### Entropy source driver interface

The entropy source driver interface lets you write drivers for Hardware Random Number Generators (HRNG), also known as True Random Number Generators (TRNG).
You can plug such drivers into any implementation of the PSA Cryptography API.

For more information, see [PSA entropy source driver interface](entropy/).

## Feedback

Arm welcomes feedback on the design of the PSA cryptography interfaces.
If you think something could be improved, please open an [issue on the Mbed TLS GitHub repository](https://github.com/ARMmbed/mbedtls/labels/api-spec).
Alternatively, if you prefer to provide your feedback privately, please email us at `mbed-crypto@arm.com`. All feedback received by email is treated confidentially.
