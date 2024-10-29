# frodoKem

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![License][license-image]](LICENSE-APACHE)
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/mikelodder7/frodoKem/actions/workflows/frodo-kem/badge.svg)

A pure rust implementation of [FrodoKEM Learning with Errors Key Encapsulation](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).

This code implements

- FrodoKEM-640 with AES and SHAKE.
- FrodoKEM-976 with AES and SHAKE.
- FrodoKEM-1344 with AES and SHAKE.

## Future work

- **Experimental** FrodoKEM ZKP of Well-Encryptedness.
- Speed up AES implementation.

## License

Licensed under

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

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
[license-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg
[downloads-image]: https://img.shields.io/crates/d/frodo-kem-rs.svg
