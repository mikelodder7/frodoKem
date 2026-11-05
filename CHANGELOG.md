# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.2]

### Security

- **Decapsulation was a decryption oracle that allowed secret-key recovery.**
  `Algorithm::decapsulate`, `DecryptionKey::decapsulate`, and
  `hazmat::Kem::decapsulate` returned the recovered message `mu'` even when the
  Fujisaki-Okamoto re-encryption check rejected the ciphertext. The shared
  secret correctly fell back to implicit rejection, but `mu'` was
  `PKE.Decrypt(S, ct)` of an attacker-chosen ciphertext. Because `B'` and `C`
  are attacker-controlled, each query is a linear query on the secret matrix
  `S`. Against a static key, an attacker could recover the full secret key on
  every parameter set with 481 to 1,009 `decapsulate()` calls if `mu'` was
  observable, or about 24,000 calls if the application revealed only an
  accept/reject bit (for example, an AEAD tag check keyed by `mu'`, as the
  crate-level example suggests). All earlier releases are affected.
  Applications that ignored the returned message, or used
  `kem::Decapsulate`, which returns only the shared secret, were not affected.
  Reported by Bhabani Sankar Das ([@007bsd](https://github.com/007bsd)); the
  same code in RustCrypto `frodo-kem` is tracked as GHSA-hhq3-76c6-9rcj.

### Fixed

- `decapsulate` now releases `mu'` only when the re-encryption check passes.
  On rejection it returns a pseudorandom message,
  `SHAKE(0x97 || s || ct)`, selected in constant time, so a rejected ciphertext
  stays indistinguishable from an accepted one and reveals nothing about `S`.
  The return types are unchanged; valid ciphertexts decapsulate exactly as
  before, and all KAT vectors still pass.
- Documentation: the `decapsulate` doc comments now describe the implicit
  rejection behavior for both the shared secret and the message.

### Added

- Regression test covering all 12 parameter sets that asserts `decapsulate`
  does not return the decryption of a rejected ciphertext.

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
