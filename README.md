# Mbed Crypto library

The Mbed cryptography library is a reference implementation of the cryptography interface of the Arm Platform Security Architecture (PSA). This is a preview release of Mbed Crypto, provided for evaluation purposes only.

## PSA cryptography API

Arm's [Platform Security Architecture (PSA)](https://developer.arm.com/architectures/security-architectures/platform-security-architecture) is a holistic set of threat models, security analyses, hardware and firmware architecture specifications, and an open source firmware reference implementation. PSA provides a recipe, based on industry best practice, that allows security to be consistently designed in, at both a hardware and firmware level.

The [PSA cryptography API](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface) provides access to a set of cryptographic primitives. It has a dual purpose. First, it can be used in a PSA-compliant platform to build services, such as secure boot, secure storage and secure communication. Second, it can also be used independently of other PSA components on any platform.

The design goals of the PSA cryptography API include:

* The API distinguishes caller memory from internal memory, which allows the library to be implemented in an isolated space for additional security. Library calls can be implemented as direct function calls if isolation is not desired, and as remote procedure calls if isolation is desired.
* The structure of internal data is hidden to the application, which allows substituting alternative implementations at build time or run time, for example, in order to take advantage of hardware accelerators.
* All access to the keys happens through handles, which allows support for external cryptoprocessors that is transparent to applications.
* The interface to algorithms is generic, favoring algorithm agility.
* The interface is designed to be easy to use and hard to accidentally misuse.

## Mbed Crypto implementation

Mbed Crypto is a reference implementation of the PSA cryptography API. It is written in portable C.

## Documentation

The Mbed Crypto library implements both the legacy Mbed TLS interfaces to cryptographic primitives (`mbedtls_xxx`) and the new PSA Cryptography interfaces (`psa_xxx`).

Documentation for the Mbed TLS interfaces in the default library configuration is available as part of the [Mbed TLS documentation](https://tls.mbed.org/api/).

For the PSA interfaces, please refer to the PSA Cryptography API documents linked from the [PSA cryptography interfaces documentation portal](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface) for an overview of the library's interfaces and a detailed description of the types, macros and functions that it provides. The API reference is available in [PDF](https://armmbed.github.io/mbed-crypto/PSA_Cryptography_API_Specification.pdf) and [HTML](https://armmbed.github.io/mbed-crypto/html/index.html) formats.

There are currently a few deviations where the library does not yet implement the latest version of the specification. Please refer to the [compliance issues on Github](https://github.com/ARMmbed/mbed-crypto/labels/compliance) for an up-to-date list.

### Browsable library documentation

To generate a local copy of the library documentation in HTML format, tailored to your compile-time configuration:

1. Make sure that [Doxygen](http://www.doxygen.nl/) is installed. We use version 1.8.11 but slightly older or more recent versions should work.
1. Run `make apidoc`.
1. Browse `apidoc/index.html` or `apidoc/modules.html`.

## Compiling

You need the following tools to build the library with the provided makefiles:

* GNU Make or a build tool that CMake supports.
* A C99 toolchain (compiler, linker, archiver).
* Python 2 or Python 3 (either will work) to generate the test code.
* Perl to run the tests.

If you have a C compiler, such as GCC or Clang, just run `make` in the top-level directory to build the library, a set of unit tests and some sample programs.

To select a different compiler, set the `CC` variable to the name or path of the compiler and linker (default: `cc`), and set `AR` to a compatible archiver (default: `ar`). For example:
```
make CC=arm-linux-gnueabi-gcc AR=arm-linux-gnueabi-ar
```
The provided makefiles pass options to the compiler that assume a GCC-like command-line syntax. To use a different compiler, you may need to pass different values for `CFLAGS`, `WARNINGS_CFLAGS` and `LDFLAGS`.

To run the unit tests on the host machine, run `make test` from the top-level directory. If you are cross-compiling, copy the test executable from the `tests` directory to the target machine.

### Compiling as a subproject

Mbed Crypto supports being built as a subproject of Mbed TLS. Mbed TLS can use Mbed Crypto for its cryptography implementation by using Mbed Crypto as a subproject.

From the Mbed TLS project repository, CMake can be invoked as follows to build Mbed TLS using Mbed Crypto's `libmbedcrypto`.
```
mkdir cmake
cd cmake
cmake .. -DUSE_CRYPTO_SUBMODULE=1
make -j
make test
```

When building Mbed Crypto as a subproject of Mbed TLS, the Mbed TLS
configuration file (config.h) is used, and not the Mbed Crypto configuration
file.

## Example programs

The `programs/` subdirectory contains sample programs that use the library. Please note that the goal of these sample programs is to demonstrate specific features of the library, and the code may need to be adapted to build a real-world application.

## Upcoming features

Future releases of this library will include:

* A driver programming interface, which makes it possible to use hardware accelerators instead of the default software implementation for chosen algorithms.
* Support for external keys to be stored and manipulated exclusively in a separate cryptoprocessor.
* A configuration mechanism to compile only the algorithms you need for your application.
* A wider set of cryptographic algorithms.

## License

Unless specifically indicated otherwise in a file, Mbed TLS files are provided under the [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) license. See the [LICENSE](LICENSE) file for the full text of this license. Contributors must accept that their contributions are made under both the Apache-2.0 AND [GPL-2.0-or-later](https://spdx.org/licenses/GPL-2.0-or-later.html) licenses. This enables LTS (Long Term Support) branches of the software to be provided under either the Apache-2.0 OR GPL-2.0-or-later licenses.

## Contributing

We gratefully accept bug reports and contributions from the community. Please see the [contributing guidelines](CONTRIBUTING.md) for details on how to do this.

## Feedback welcome

Arm welcomes feedback on the design of the API. If you think something could be improved, please open an issue on our Github repository. Alternatively, if you prefer to provide your feedback privately, please email us at [`mbed-crypto@arm.com`](mailto:mbed-crypto@arm.com). All feedback received by email is treated confidentially.
