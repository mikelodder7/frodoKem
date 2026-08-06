# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1]

### Added

- `hazmat::Expanded::expand_a_rows`, which visits the rows of matrix A in small
  blocks without materializing the full `N x N` matrix. A default implementation
  falls back to `expand_a`, so external `Expanded` implementors are unaffected.
- `hazmat::Kem::mul_add_as_plus_e_from_seed` and
  `hazmat::Kem::mul_add_sa_plus_e_from_seed`, fused multiply-accumulate
  operations that generate the rows of A on the fly from `seed_a`.

### Changed

- Key generation, encapsulation, and decapsulation no longer allocate the full
  `N x N` matrix A. Peak transient memory for A drops from ~819 KB / ~1.9 MB /
  ~3.6 MB (640 / 976 / 1344) to at most 64 rows (~168 KB at 1344) for the AES
  generators and a single row (~2.7 KB at 1344) for the SHAKE generators.
- Performance (criterion, Apple M-series, vs. 0.9.0): encapsulation and
  decapsulation are 41-45% faster for AES variants and 15-17% faster for SHAKE
  variants; SHAKE key generation is unchanged; AES key generation is ~8% slower
  as a consequence of streaming generation (accepted trade-off for the memory
  reduction).

### Fixed

- Big-endian targets: byte-order conversion of SHAKE/AES output used
  `u16::to_be`, which is the identity function on big-endian hosts, instead of
  `u16::swap_bytes`. All matrix-generation and sampling paths were affected on
  big-endian platforms. Little-endian targets were never affected.
- OpenSSL backends: the key generation, encapsulation, and decapsulation flows
  no longer leak OpenSSL contexts (previously one `EVP_CIPHER_CTX` per AES
  `expand_a` call and one `EVP_MD_CTX` per generated row per SHAKE `expand_a`
  call).
- Documentation: the ephemeral `Algorithm` variants were documented as their
  standard FrodoKEM counterparts, `hazmat::Kem::add` was documented as "Matrix
  subtraction", `Ciphertext` was described as a "ciphertext key", the matrix-A
  generators were documented as generating "column-wise" when both generate
  row-wise, and various grammar and spelling issues in README.md, SECURITY.md,
  and doc comments were corrected.

## [0.9.0] and earlier

See the [git tag history](https://github.com/mikelodder7/frodoKem/tags) for
releases prior to this changelog.
