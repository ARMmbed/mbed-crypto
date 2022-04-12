# PSA cryptography interfaces

This page contains technical information about the cryptography interfaces in the Arm Platform Security Architecture (PSA) and related documents and software.
For more information about the Platform Security Architecture, see [the Arm Developer website](https://developer.arm.com/architectures/security-architectures/platform-security-architecture).

## Application programming interface

The PSA Cryptography API is a C programming interface for applications that wish to store cryptographic keys and use them to perform cryptographic operations.

**Reference documentation**:
[HTML](../html/index.html),
[PDF](../PSA_Cryptography_API_Specification.pdf)

Past versions:

* 1.0.1:
  [HTML](../1.0.1/html/index.html),
  [PDF](../1.0.1/PSA_Cryptography_API_Specification.pdf)
* 1.1.0:
  [HTML](../1.1.0/html/index.html),
  [PDF](../1.1.0/PSA_Cryptography_API_Specification.pdf)

**Reference implementation**: [Mbed TLS](https://github.com/ARMmbed/mbed-tls)

### PAKE extension

The PAKE extension is a draft to extend the PSA Cryptography API to support PAKE (password-authenticated key exchange) algorithms. It is currently in draft status. Arm intends to eventually integrate it as an optional part of the API. As long as this extension has draft status, it may undergo incompatible changes without notice.

Versions:

* 0-bet.0:
  [HTML](../1.1_PAKE_Extension.0-bet.0/html/index.html),
  [PDF](../1.1_PAKE_Extension.0-bet.0/psa_crypto_api_pake_ext.pdf)

## Hardware abstraction layer

### Unified driver interface

There is work in progress to define a PSA cryptography driver interface, allowing an implementation of the PSA Cryptography API to make use of dedicated hardware (accelerators, secure elements, random generators, etc.) or other external systems such as a remote key store.
The driver interface is being tried out in Mbed TLS. Arm expects to make it an official PSA specification once it has been sufficiently validated.

For more information, please see the [proposed driver interface](https://github.com/ARMmbed/mbedtls/blob/development/docs/proposed/psa-driver-interface.md) as well as the [ongoing specification and implementation effort](https://github.com/ARMmbed/mbedtls/issues?q=+label%3AHwDrivers+).

### Dynamic secure element driver interface

The dynamic secure element driver interface lets you write drivers for external cryptoprocessors such as secure elements (SE), smart cards and hardware security modules (HSM) that perform operations on keys that never leave the external processor and are accessed only through opaque handles.
Such drivers can be loaded dynamically into an implementation of the PSA Cryptography API such as Mbed TLS.

Work on this interface is currently frozen. The [unified driver interface](#unified-driver-interface) replaces the older dynamic secure element driver for most purposes. The older interface has the advantage of allowing drivers to be dynamically loaded. If there is widespread demand for dynamic loading of secure element drivers, Arm may revive the effort on the older interface or merge it into the unified interface.

For more information, see [PSA secure element driver interface](se/).

## Feedback

Arm welcomes feedback on the design of the PSA cryptography interfaces.
If you think something could be improved, please open an [issue on the Mbed TLS GitHub repository](https://github.com/ARMmbed/mbedtls/labels/api-spec).
Alternatively, if you prefer to provide your feedback privately, please email us at `mbed-crypto@arm.com`. All feedback received by email is treated confidentially.
