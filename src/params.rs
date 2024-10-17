/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

#[cfg(any(feature = "frodo640aes", feature = "frodo640shake"))]
/// The FrodoKEM-640 parameters
pub const FRODO_640_PARAMS: Params = Params {
    n: 640,
    n_bar: 8,
    log_q: 15,
    q: 1 << 15,
    extracted_bits: 2,
    stripe_step: 8,
    parallel: 4,
    bytes_seed_a: 16,
    bytes_mu: (2 * 8 * 8) / 8,
    bytes_pk_hash: 16,
    cdf_table: &[
        4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
    ],
    claimed_nist_level: 1,
    public_key_length: 9616,
    secret_key_length: 19888,
    ciphertext_length: 9720,
    shared_secret_length: 16,
};

#[cfg(any(feature = "frodo976aes", feature = "frodo976shake"))]
/// The FrodoKEM-976 parameters
pub const FRODO_976_PARAMS: Params = Params {
    n: 976,
    n_bar: 8,
    log_q: 16,
    q: 1 << 16,
    extracted_bits: 3,
    stripe_step: 8,
    parallel: 4,
    bytes_seed_a: 16,
    bytes_mu: (3 * 8 * 8) / 8,
    bytes_pk_hash: 24,
    cdf_table: &[
        5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767,
    ],
    claimed_nist_level: 3,
    public_key_length: 15632,
    secret_key_length: 31296,
    ciphertext_length: 15744,
    shared_secret_length: 24,
};

#[cfg(any(feature = "frodo1344aes", feature = "frodo1344shake"))]
/// The FrodoKEM-1344 parameters
pub const FRODO_1344_PARAMS: Params = Params {
    n: 1344,
    n_bar: 8,
    log_q: 16,
    q: 1 << 16,
    extracted_bits: 4,
    stripe_step: 8,
    parallel: 4,
    bytes_seed_a: 16,
    bytes_mu: (4 * 8 * 8) / 8,
    bytes_pk_hash: 32,
    cdf_table: &[9142, 23462, 30338, 32361, 32725, 32765, 32767],
    claimed_nist_level: 5,
    public_key_length: 21520,
    secret_key_length: 43088,
    ciphertext_length: 21632,
    shared_secret_length: 32,
};

/// The FrodoKEM parameters
/// where `T` is the length of the CDF table
#[derive(Copy, Clone, Debug)]
pub struct Params {
    /// The number of elements in the ring
    pub n: usize,
    /// The number of rows
    pub n_bar: usize,
    /// The log of the modulus
    pub log_q: usize,
    /// The modulus
    pub q: usize,
    /// The number of bits extracted when expanding the seed
    pub extracted_bits: usize,
    /// The stripe step
    pub stripe_step: usize,
    /// The number of parallel operations
    pub parallel: usize,
    /// The number of bytes in the seed for A
    pub bytes_seed_a: usize,
    /// The number of bytes in mu
    pub bytes_mu: usize,
    /// The number of bytes in the public key hash
    pub bytes_pk_hash: usize,
    /// The CDF table
    pub cdf_table: &'static [u16],
    /// The claimed NIST level
    pub claimed_nist_level: usize,
    /// The length of the public key
    pub public_key_length: usize,
    /// The length of the secret key
    pub secret_key_length: usize,
    /// The length of the ciphertext
    pub ciphertext_length: usize,
    /// The length of the shared secret
    pub shared_secret_length: usize,
}
