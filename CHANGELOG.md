# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0]

### Changed

- **Breaking:** `Algorithm::decapsulate`, `DecryptionKey::decapsulate`, and
  `hazmat::Kem::decapsulate` now return the recovered message `mu'` as
  `Zeroizing<Vec<u8>>`, so it is wiped when dropped. It derefs to `Vec<u8>`;
  compare with `*mu` or `mu.as_slice()`. `Zeroizing` is re-exported from the
  crate root so callers can name it without depending on `zeroize`.
- **Breaking:** `DecryptionKey::decapsulate` no longer takes an unused generic
  parameter `B`, which could not be inferred and forced a turbofish at every
  call site.
- **Breaking:** `Algorithm::encryption_key_from_decryption_key` now returns
  `FrodoResult<EncryptionKey>`, and `From<&DecryptionKey> for EncryptionKey`
  is replaced by `TryFrom`. Both reject a key from another algorithm with
  `Error::AlgorithmMismatch` and a wrong-length key with
  `Error::InvalidSecretKeyLength`.

- **Breaking (hazmat):** `Expanded::expand_a_rows` is now the required method
  and `expand_a` is provided on top of it. The four full-matrix `expand_a`
  implementations were removed; the KEM only ever used the row-streaming path.

### Added

- `Algorithm::decapsulate_shared_secret` and
  `DecryptionKey::decapsulate_shared_secret` return only the shared secret and
  skip message recovery (one SHAKE and two allocations less per call).

### Security

- Zeroize sensitive intermediate values as soon as they are no longer needed,
  matching the FIPS 203 §3.3 requirement for ML-KEM:
  - SHAKE hasher state (which absorbs `seedSE`, `mu || salt`, `k`, and `s`) is
    wiped on drop by enabling the `shake` `zeroize` feature.
  - Decapsulation wipes the re-encryption matrices `B''` and `C'`, which are
    derived from `mu'`.
  - Temporary heap copies made during serde serialization and deserialization
    (hex strings and byte buffers) are wiped.
  - `TryFrom<Vec<u8>>` and `TryFrom<Box<[u8]>>` wipe the consumed buffer.
  - Binary serde deserialization of the top-level types now requests an owned
    byte buffer (`deserialize_byte_buf`) and wipes it, so formats that hand
    over a `Vec<u8>` (such as `serde_bare`) no longer drop an unwiped copy of
    the key or shared secret.

### Fixed

- `hazmat::Kem::generate_keypair_from_seed` checked the seed length only in
  debug builds; a wrong-length seed in release either panicked on a slice or
  silently fed the surplus into the matrix-A seed. It now panics in all builds,
  and the panic conditions of the hazmat `encapsulate` and
  `generate_keypair_from_seed` methods are documented.
- The `kem` adapter's compile-time key, ciphertext, and shared-secret sizes
  are now asserted equal to the corresponding `Params` constants, so a size
  typo fails the build instead of panicking inside decapsulation.
- Corrected an inverted comment on the shared-secret selection in
  `decapsulate`; the code was already right.
- The `kem` module documents that the arrays returned by the `kem` traits are
  not zeroized and are the caller's responsibility.
- The OpenSSL-backed full-matrix `expand_a` implementations leaked an
  `EVP_CIPHER_CTX` (AES) or one `EVP_MD_CTX` per row (SHAKE) on every call.
  They are gone with the `Expanded` change above, and the OpenSSL SHAKE row
  path now allocates one context per expansion instead of one per row.
- The generic bit-packing `unpack` could spin if the input ran out mid-word.
  Unreachable with the validated lengths the crate passes, but it now stops.

### Performance

- Decapsulation writes the implicit-rejection message straight into the output
  buffer and selects in place, removing one allocation and one pass.
- The secret matrix `S` is converted to and from bytes with `as_chunks` instead
  of per-element indexing.
- `ct_select` uses the word-coalesced constant-time slice assignment from
  `ctutils` instead of a byte loop.
- `TryFrom<Vec<u8>>` and `TryFrom<Box<[u8]>>` move the buffer into the new
  value instead of copying it.

- `encryption_key_from_decryption_key` and `EncryptionKey::from(&DecryptionKey)`
  sliced the secret key without checking its length or algorithm. A short key
  (for example `DecryptionKey::default()`) or a key from a smaller parameter set
  panicked; a key from a larger parameter set silently returned a wrong public
  key labeled with the requested algorithm.
- Binary deserialization of `EncryptionKey`, `DecryptionKey`, `Ciphertext`, and
  `SharedSecret` panicked on an empty byte string; it now returns an error.

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

### Changed

- MSRV raised from 1.85 to 1.89 and now declared as `rust-version` in
  `Cargo.toml`. `aes` 0.9.3 and later require Rust 1.89.
- Packing and unpacking use `slice::as_chunks` for their fixed-size chunks.
- `rstest` dev-dependency bumped to 0.28.

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
