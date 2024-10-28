/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{Error, Expanded, FrodoResult, Kem, Params, Sample};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A FrodoKEM ciphertext
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Ciphertext<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for Ciphertext<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: Params> Default for Ciphertext<P> {
    fn default() -> Self {
        Self(vec![0u8; P::CIPHERTEXT_LENGTH], PhantomData)
    }
}

impl<P: Params> Ciphertext<P> {
    /// Convert a slice of bytes into a ciphertext
    pub fn from_slice(bytes: &[u8]) -> FrodoResult<Self> {
        if bytes.len() != P::CIPHERTEXT_LENGTH {
            return Err(Error::InvalidCiphertextLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec(), PhantomData))
    }

    /// Returns a reference to the c1 component
    pub fn c1(&self) -> &[u8] {
        &self.0[..P::LOG_Q_X_N_X_N_BAR_DIV_8]
    }

    /// Returns a mutable reference to the c1 component
    pub fn c1_mut(&mut self) -> &mut [u8] {
        &mut self.0[..P::LOG_Q_X_N_X_N_BAR_DIV_8]
    }

    /// Returns a reference to the c2 component
    pub fn c2(&self) -> &[u8] {
        &self.0[P::LOG_Q_X_N_X_N_BAR_DIV_8..]
    }

    /// Returns a mutable reference to the c2 component
    pub fn c2_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::LOG_Q_X_N_X_N_BAR_DIV_8..]
    }
}

/// A FrodoKEM public key
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PublicKey<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for PublicKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: Params> Default for PublicKey<P> {
    fn default() -> Self {
        Self(vec![0u8; P::PUBLIC_KEY_LENGTH], PhantomData)
    }
}

impl<P: Params> From<&SecretKey<P>> for PublicKey<P> {
    fn from(value: &SecretKey<P>) -> Self {
        Self(value.public_key().to_vec(), PhantomData)
    }
}

impl<P: Params> PublicKey<P> {
    /// Convert a slice of bytes into a public key
    pub fn from_slice(bytes: &[u8]) -> FrodoResult<Self> {
        if bytes.len() != P::PUBLIC_KEY_LENGTH {
            return Err(Error::InvalidPublicKeyLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec(), PhantomData))
    }

    /// Returns a reference to the seed A
    pub fn seed_a(&self) -> &[u8] {
        &self.0[..P::BYTES_SEED_A]
    }

    /// Returns a mutable reference to the seed A
    pub fn seed_a_mut(&mut self) -> &mut [u8] {
        &mut self.0[..P::BYTES_SEED_A]
    }

    /// Returns a reference to the matrix B
    pub fn matrix_b(&self) -> &[u8] {
        &self.0[P::BYTES_SEED_A..]
    }

    /// Returns a mutable reference to the matrix B
    pub fn matrix_b_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::BYTES_SEED_A..]
    }
}

pub(crate) struct PublicKeyRef<'a, P: Params>(pub(crate) &'a [u8], pub(crate) PhantomData<P>);

impl<'a, P: Params> AsRef<[u8]> for PublicKeyRef<'a, P> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a, P: Params> PublicKeyRef<'a, P> {
    pub fn from_slice(bytes: &'a [u8]) -> FrodoResult<Self> {
        if bytes.len() != P::PUBLIC_KEY_LENGTH {
            return Err(Error::InvalidPublicKeyLength(bytes.len()));
        }
        Ok(Self(bytes, PhantomData))
    }

    pub(crate) fn seed_a(&self) -> &[u8] {
        &self.0[..P::BYTES_SEED_A]
    }

    pub(crate) fn matrix_b(&self) -> &[u8] {
        &self.0[P::BYTES_SEED_A..]
    }
}

/// A FrodoKEM secret key
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SecretKey<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for SecretKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: Params> Default for SecretKey<P> {
    fn default() -> Self {
        Self(vec![0u8; P::SECRET_KEY_LENGTH], PhantomData)
    }
}

impl<P: Params> Zeroize for SecretKey<P> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<P: Params> ZeroizeOnDrop for SecretKey<P> {}

impl<P: Params> SecretKey<P> {
    /// Convert a slice of bytes into a secret key
    pub fn from_slice(bytes: &[u8]) -> FrodoResult<Self> {
        if bytes.len() != P::SECRET_KEY_LENGTH {
            return Err(Error::InvalidSecretKeyLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec(), PhantomData))
    }

    /// Returns a reference to the shared secret
    pub fn random_s(&self) -> &[u8] {
        &self.0[..P::SHARED_SECRET_LENGTH]
    }

    /// Returns a mutable reference to the shared secret
    pub fn random_s_mut(&mut self) -> &mut [u8] {
        &mut self.0[..P::SHARED_SECRET_LENGTH]
    }

    /// Returns a reference to the public key
    pub fn public_key(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH]
    }

    /// Returns a mutable reference to the public key
    pub fn public_key_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH]
    }

    /// Returns a reference to the matrix s
    pub fn matrix_s(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH
            ..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR]
    }

    /// Returns a mutable reference to the matrix s
    pub fn matrix_s_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH
            ..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR]
    }

    /// Returns a reference to the hash of the public key
    pub fn hpk(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR..]
    }

    /// Returns a mutable reference to the hash of the public key
    pub fn hpk_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR..]
    }
}

/// A FrodoKEM shared secret
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SharedSecret<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for SharedSecret<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: Params> Default for SharedSecret<P> {
    fn default() -> Self {
        Self(vec![0u8; P::SHARED_SECRET_LENGTH], PhantomData)
    }
}

impl<P: Params> Zeroize for SharedSecret<P> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<P: Params> ZeroizeOnDrop for SharedSecret<P> {}

impl<P: Params> SharedSecret<P> {
    /// Convert a slice of bytes into a shared secret
    pub fn from_slice(bytes: &[u8]) -> FrodoResult<Self> {
        if bytes.len() != P::SHARED_SECRET_LENGTH {
            return Err(Error::InvalidSharedSecretLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec(), PhantomData))
    }
}

/// The FrodoKEM scheme
#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct FrodoKem<P: Params, E: Expanded, S: Sample>(pub PhantomData<(P, E, S)>);

impl<P: Params, E: Expanded, S: Sample> Params for FrodoKem<P, E, S> {
    type Shake = P::Shake;
    const N: usize = P::N;
    const LOG_Q: usize = P::LOG_Q;
    const EXTRACTED_BITS: usize = P::EXTRACTED_BITS;
    const CDF_TABLE: &'static [u16] = P::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = P::CLAIMED_NIST_LEVEL;
    const SHARED_SECRET_LENGTH: usize = P::SHARED_SECRET_LENGTH;
}

impl<P: Params, E: Expanded, S: Sample> Expanded for FrodoKem<P, E, S> {
    const METHOD: &'static str = E::METHOD;
    fn expand_a(seed_a: &[u8], a: &mut [u16]) {
        E::expand_a(seed_a, a)
    }
}

impl<P: Params, E: Expanded, S: Sample> Sample for FrodoKem<P, E, S> {
    fn sample(s: &mut [u16]) {
        S::sample(s)
    }
}

impl<P: Params, E: Expanded, S: Sample> Kem for FrodoKem<P, E, S> {}

#[cfg(any(feature = "frodo640aes", feature = "frodo640shake"))]
/// Frodo640 parameters
#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct Frodo640;

#[cfg(any(feature = "frodo640aes", feature = "frodo640shake"))]
impl Params for Frodo640 {
    type Shake = sha3::Shake128;
    const N: usize = 640;
    const LOG_Q: usize = 15;
    const EXTRACTED_BITS: usize = 2;
    const CDF_TABLE: &'static [u16] = &[
        4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
    ];
    const CLAIMED_NIST_LEVEL: usize = 1;
    const SHARED_SECRET_LENGTH: usize = 16;
}

#[cfg(any(feature = "frodo976aes", feature = "frodo976shake"))]
/// Frodo976 parameters
#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct Frodo976;

#[cfg(any(feature = "frodo976aes", feature = "frodo976shake"))]
impl Params for Frodo976 {
    type Shake = sha3::Shake256;
    const N: usize = 976;
    const LOG_Q: usize = 16;
    const EXTRACTED_BITS: usize = 3;
    const CDF_TABLE: &'static [u16] = &[
        5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767,
    ];
    const CLAIMED_NIST_LEVEL: usize = 3;
    const SHARED_SECRET_LENGTH: usize = 24;
}

#[cfg(any(feature = "frodo1344aes", feature = "frodo1344shake"))]
/// Frodo1344 parameters
#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct Frodo1344;

#[cfg(any(feature = "frodo1344aes", feature = "frodo1344shake"))]
impl Params for Frodo1344 {
    type Shake = sha3::Shake256;
    const N: usize = 1344;
    const LOG_Q: usize = 16;
    const EXTRACTED_BITS: usize = 4;
    const CDF_TABLE: &'static [u16] = &[9142, 23462, 30338, 32361, 32725, 32765, 32767];
    const CLAIMED_NIST_LEVEL: usize = 5;
    const SHARED_SECRET_LENGTH: usize = 32;
}

#[cfg(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes"
))]
/// Generate matrix A (N x N) column-wise using AES-128
///
/// See Algorithm 7 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20190215.pdf)
#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct FrodoAes<P: Params>(pub(crate) PhantomData<P>);

impl<P: Params> Expanded for FrodoAes<P> {
    const METHOD: &'static str = "Aes";

    fn expand_a(seed_a: &[u8], a: &mut [u16]) {
        use aes::{
            cipher::{BlockEncrypt, KeyInit, KeySizeUser},
            Aes128Enc, Block,
        };

        debug_assert_eq!(a.len(), P::N_X_N);
        debug_assert_eq!(seed_a.len(), P::BYTES_SEED_A);
        debug_assert_eq!(seed_a.len(), <Aes128Enc as KeySizeUser>::key_size());

        let enc = Aes128Enc::new_from_slice(seed_a).expect("a valid key size of 16 bytes");

        let mut in_block = Block::default();
        let mut out_block = Block::default();
        for i in 0..P::N {
            let ii = i as u16;
            in_block[..2].copy_from_slice(&ii.to_le_bytes());
            let row = i * P::N;
            for j in (0..P::N).step_by(P::STRIPE_STEP) {
                let jj = j as u16;
                in_block[2..4].copy_from_slice(&jj.to_le_bytes());
                enc.encrypt_block_b2b(&in_block, &mut out_block);

                for k in 0..P::STRIPE_STEP {
                    a[row + j + k] =
                        u16::from_le_bytes([out_block[2 * k], out_block[2 * k + 1]]) & P::Q_MASK;
                }
            }
        }
    }
}

#[cfg(any(
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake"
))]
/// Generate matrix A (N x N) column-wise using SHAKE-128
///
/// See Algorithm 8 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20190215.pdf)
#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct FrodoShake<P: Params>(pub PhantomData<P>);

#[cfg(any(
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake"
))]
impl<P: Params> Expanded for FrodoShake<P> {
    const METHOD: &'static str = "SHAKE";
    fn expand_a(seed_a: &[u8], a: &mut [u16]) {
        use sha3::{
            digest::{ExtendableOutputReset, Update},
            Shake128,
        };

        debug_assert_eq!(a.len(), P::N_X_N);
        debug_assert_eq!(seed_a.len(), P::BYTES_SEED_A);

        let mut a_row = vec![0u8; P::TWO_N];
        let mut seed_separated = vec![0u8; P::TWO_PLUS_BYTES_SEED_A];
        let mut shake = Shake128::default();

        seed_separated[2..].copy_from_slice(seed_a);

        for i in 0..P::N {
            let ii = i * P::N;

            seed_separated[0..2].copy_from_slice(&(i as u16).to_le_bytes());
            shake.update(&seed_separated);
            shake.finalize_xof_reset_into(&mut a_row);

            for j in 0..P::N {
                a[ii + j] = u16::from_le_bytes([a_row[j * 2], a_row[j * 2 + 1]]);
            }
        }
    }
}

/// Generate sample noise using a CDF
#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct FrodoCdfSample<P: Params>(pub PhantomData<P>);

impl<P: Params> Sample for FrodoCdfSample<P> {
    fn sample(s: &mut [u16]) {
        for s_i in s.iter_mut() {
            let mut sample = 0u16;
            let prnd = *s_i >> 1; // Drop the least significant bit
            let sign = *s_i & 1; // Get the least significant bit

            for cdf in P::CDF_TABLE {
                sample = sample.wrapping_add(cdf.wrapping_sub(prnd) >> 15);
            }

            *s_i = (sign.wrapping_neg() ^ sample).wrapping_add(sign);
        }
    }
}
