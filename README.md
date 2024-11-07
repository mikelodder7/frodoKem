# FrodoKem

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/mikelodder7/frodoKem/actions/workflows/frodo-kem.yml/badge.svg)
![MSRV][msrv-image]

A pure rust implementation of 
- [FrodoKEM Learning with Errors Key Encapsulation](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
- [ISO Standard](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf)
- [ISO Standard Annex](https://frodokem.org/files/FrodoKEM-annex-20230418.pdf)

It's submission was included in NIST's PQ Round 3 competition.

## ⚠️ Security Warning

This crate has been tested against the test vectors provided by the FrodoKEM team
and been rigorously tested for correctness, performance, and security. It has 
also been tested against opensafequatum's liboqs library to compatibility and correctness.

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

This crate requires **Rust 1.82** at a minimum.

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

eFrodoKEM is a variant of FrodoKEM that is meant to be used one-time only. Using more than once
is considered a security risk.

When in doubt use the FrodoKEM algorithm variants.

## Future work

- Speed up AES implementation.

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
[msrv-image]: https://img.shields.io/badge/rustc-1.82+-blue.svg