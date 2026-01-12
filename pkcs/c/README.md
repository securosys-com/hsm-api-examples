# PKCS#11 C Examples

The examples in this directory show how to use the PKCS#11 interface from C.

## Prerequisites

Install the Primus PKCS#11 Provider on your machine and configure it with the `ppin` tool
as described [in the documentation](https://docs.securosys.com/pkcs/overview).

On Debian/Ubuntu, the following packages are required:

- `build-essential`
- `libbotan-2-dev` (some examples use utils from Botan)

The examples were tested with the Primus PKCS#11 Provider 2.4.0 on Ubuntu 24.04.

## Usage

```sh
make

./build/attestation
./build/rsa
./build/slip10
```

## References

- [PKCS#11 specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/pkcs11-spec-v3.1.html)
- [Securosys vendor extensions to PKCS#11](https://docs.securosys.com/pkcs/vendor/overview)
