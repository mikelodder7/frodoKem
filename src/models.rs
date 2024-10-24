/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{Expanded, Kem, Params, Sample};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A FrodoKEM ciphertext
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ciphertext<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

/// A FrodoKEM public key
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> Default for PublicKey<P> {
    fn default() -> Self {
        Self(vec![0u8; P::PUBLIC_KEY_LENGTH], PhantomData)
    }
}

impl<P: Params> PublicKey<P> {
    pub(crate) fn seed_a(&self) -> &[u8] {
        &self.0[..P::BYTES_SEED_A]
    }

    pub(crate) fn seed_a_mut(&mut self) -> &mut [u8] {
        &mut self.0[..P::BYTES_SEED_A]
    }

    pub(crate) fn matrix_b(&self) -> &[u8] {
        &self.0[P::BYTES_SEED_A..]
    }

    pub(crate) fn matrix_b_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::BYTES_SEED_A..]
    }
}

/// A FrodoKEM secret key
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecretKey<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

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
    pub fn random_s(&self) -> &[u8] {
        &self.0[..P::SHARED_SECRET_LENGTH]
    }

    pub fn random_s_mut(&mut self) -> &mut [u8] {
        &mut self.0[..P::SHARED_SECRET_LENGTH]
    }

    pub fn public_key(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH]
    }

    pub fn public_key_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH]
    }

    pub fn matrix_s(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH
            ..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR]
    }

    pub fn matrix_s_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH
            ..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR]
    }

    pub fn hpk(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR..]
    }

    pub fn hpk_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR..]
    }
}

/// A FrodoKEM shared secret
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SharedSecret<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

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

#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct FrodoKem<P: Params, E: Expanded, S: Sample>(pub PhantomData<(P, E, S)>);

impl<P: Params, E: Expanded, S: Sample> Params for FrodoKem<P, E, S> {
    type Shake = P::Shake;
    const N: usize = P::N;
    const N_BAR: usize = P::N_BAR;
    const LOG_Q: usize = P::LOG_Q;
    const EXTRACTED_BITS: usize = P::EXTRACTED_BITS;
    const STRIPE_STEP: usize = P::STRIPE_STEP;
    const PARALLEL: usize = P::PARALLEL;
    const BYTES_SEED_A: usize = P::BYTES_SEED_A;
    const BYTES_MU: usize = P::BYTES_MU;
    const BYTES_PK_HASH: usize = P::BYTES_PK_HASH;
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
#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct Frodo640;

#[cfg(any(feature = "frodo640aes", feature = "frodo640shake"))]
impl Params for Frodo640 {
    type Shake = sha3::Shake128;
    const N: usize = 640;
    const N_BAR: usize = 8;
    const LOG_Q: usize = 15;
    const EXTRACTED_BITS: usize = 2;
    const STRIPE_STEP: usize = 8;
    const PARALLEL: usize = 4;
    const BYTES_SEED_A: usize = 16;
    const BYTES_MU: usize = 16;
    const BYTES_PK_HASH: usize = 16;
    const CDF_TABLE: &'static [u16] = &[
        4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
    ];
    const CLAIMED_NIST_LEVEL: usize = 1;
    const SHARED_SECRET_LENGTH: usize = 16;
}

#[cfg(any(
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake"
))]
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
        use sha3::digest::{ExtendableOutputReset, Update};

        let mut a_row = vec![0u8; P::TWO_N];
        let mut seed_separated = vec![0u8; P::TWO_PLUS_BYTES_SEED_A];
        let mut shake = P::Shake::default();

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

#[derive(
    Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub struct FrodoCdfSample<P: Params>(pub PhantomData<P>);

impl<P: Params> Sample for FrodoCdfSample<P> {
    fn sample(s: &mut [u16]) {
        let n = s.len();
        for i in 0..n {
            let mut sample = 0u16;
            let prnd = s[i] >> 1; // Drop the least significant bit
            let sign = s[i] & 1; // Get the least significant bit

            for cdf in P::CDF_TABLE {
                sample = sample.wrapping_add(cdf.wrapping_sub(prnd) >> 15);
            }

            s[i] = (sign.wrapping_neg() ^ sample).wrapping_add(sign);
        }
    }
}

// #[cfg(any(
//     feature = "frodo640shake",
//     feature = "frodo976shake",
//     feature = "frodo1344shake"
// ))]
// #[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
// pub struct FrodoShake;

// #[cfg(any(
//     feature = "frodo640shake",
//     feature = "frodo976shake",
//     feature = "frodo1344shake"
// ))]
// impl ExpandSeedA for FrodoShake {
//     const METHOD: &'static str = "SHAKE";
//
//     fn expand_a<P: FrodoCore>(seed_a: &[u8; <P as FrodoCore>::BYTES_SEED_A]) -> [u16; <P as FrodoCore>::N_X_N] {
//         use sha3::digest::{ExtendableOutputReset, Update, XofReader};
//
//         let mut a = [0u16; P::N_X_N];
//         let mut a_row = [0u8; P::TWO_N];
//         let mut seed_separated = [0u8; P::TWO_PLUS_BYTES_SEED_A];
//         let mut shake = sha3::Shake128::default();
//
//         seed_separated[2..].copy_from_slice(seed_a);
//
//         for i in 0..P::N {
//             seed_separated[0..2].copy_from_slice(&i.to_le_bytes());
//             shake.update(&seed_separated);
//             let mut read = shake.finalize_xof_reset();
//             read.read(&mut a_row);
//
//             for j in 0..P::N {
//                 a[i * P::N + j] = u16::from_le_bytes([a_row[j * 2], a_row[j * 2 + 1]]);
//             }
//         }
//
//         a
//     }
// }
