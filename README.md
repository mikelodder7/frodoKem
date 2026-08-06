# FrodoKem

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/mikelodder7/frodoKem/actions/workflows/frodo-kem.yml/badge.svg)
[![codecov](https://codecov.io/gh/mikelodder7/frodoKem/branch/main/graph/badge.svg)](https://codecov.io/gh/mikelodder7/frodoKem)
![MSRV][msrv-image]

A pure Rust implementation of FrodoKEM and eFrodoKEM as specified in
[ISO/IEC 18033-2:2006/Amd 2:2026][iso-standard].

FrodoKEM was an alternate candidate in round 3 of the NIST Post-Quantum
Cryptography Standardization Project and is now standardized by ISO.

## ISO conformance

This crate implements the `Frodo.KeyGen`, `Frodo.Encaps`, and `Frodo.Decaps`
mathematical functions from Clause 14 of ISO/IEC 18033-2:2006/Amd 2:2026 for
all twelve parameter sets listed below.

Algorithmic conformance is checked against all 1,200 known-answer tests from
the FrodoKEM team's [official reference implementation][reference-kats]:
100 cases for each standard and ephemeral AES and SHAKE parameter set. The
tests verify deterministic key generation, encapsulation, and decapsulation
outputs. Additional tests exercise implicit rejection of modified ciphertexts,
parameter sizes, serialization, and interoperability with liboqs.

Based on a clause-by-clause implementation review and the complete official
KAT suite, this crate conforms to the FrodoKEM algorithms and parameter sets
specified by Clause 14 of ISO/IEC 18033-2:2006/Amd 2:2026.

This conformance assessment has not been independently verified by a third
party. The crate has not received ISO certification, an accredited
conformance assessment, or an independent security audit. See the detailed
[conformance review](CONFORMANCE.md) for the evidence and limitations behind
the claim.

## ⚠️ Security Warning

This crate has been tested against the test vectors provided by the FrodoKEM
team and for interoperability with Open Quantum Safe's
[liboqs](https://github.com/open-quantum-safe/liboqs).

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

This crate requires **Rust 1.85** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## Details

This crate provides the following FrodoKEM algorithms:

- [x] FrodoKEM-640-AES ✅
- [x] FrodoKEM-976-AES ✅
- [x] FrodoKEM-1344-AES ✅
- [x] FrodoKEM-640-SHAKE ✅
- [x] FrodoKEM-976-SHAKE ✅
- [x] FrodoKEM-1344-SHAKE ✅
- [x] eFrodoKEM-640-AES ✅
- [x] eFrodoKEM-976-AES ✅
- [x] eFrodoKEM-1344-AES ✅
- [x] eFrodoKEM-640-SHAKE ✅
- [x] eFrodoKEM-976-SHAKE ✅
- [x] eFrodoKEM-1344-SHAKE ✅

eFrodoKEM is intended only for applications that guarantee a small number of
ciphertexts per public key (for example, at most 2<sup>8</sup>). Prefer standard
FrodoKEM unless that usage restriction is enforced by the application.

When in doubt, use the FrodoKEM algorithm variants.

Keypairs can also be generated deterministically with
`Algorithm::generate_keypair_from_seed`. The required seed length is exposed as
`Algorithm::params().key_seed_length`; inputs of any other length return an
error. Callers remain responsible for generating and protecting seed material
with the same care as a secret key.

## Expanding matrix A

### NOTE on AES

To speed up AES, there are a few options available:

- `RUSTFLAGS="--cfg aes_armv8" cargo build --release` ensures that the ARMv8 AES instructions are used if available.
- `frodo-kem-rs = { version = "0.9", features = ["openssl"] }` uses OpenSSL for AES.

By default, the `aes` crate auto-detects the best AES implementation for x86 and
x86_64 platforms, but not on ARMv8, where it defaults to the software
implementation as of this writing.
To enable the ARMv8 AES instructions, the `aes_armv8` flag is enabled in the `.cargo/config.toml` file in this crate.

Enabling `openssl` and `aesni` provides the fastest AES algorithms.

OpenSSL tends to be faster than the `aes` Rust crate implementation by about 10-15% on ARMv8.

### NOTE on SHAKE

SHAKE auto-detects the best implementation for your platform, or, like AES, you can enable the `openssl` feature for it as well.

On ARMv8, the Rust SHAKE implementation is faster than the OpenSSL implementation by about 22-25%.

## Serialization

This crate has been tested against the following `serde` compatible formats:

- [x] serde_bare
- [x] postcard
- [x] serde_cbor
- [x] serde_json
- [x] serde_yaml
- [x] toml

## License

Licensed under

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/frodo-kem-rs.svg
[crate-link]: https://crates.io/crates/frodo-kem-rs
[docs-image]: https://docs.rs/frodo-kem-rs/badge.svg
[docs-link]: https://docs.rs/frodo-kem-rs/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/frodo-kem-rs.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[iso-standard]: https://www.iso.org/standard/86890.html
[reference-kats]: https://github.com/microsoft/PQCrypto-LWEKE/tree/7a4e7219d06305e16aef734213001cd8fefbcc14
