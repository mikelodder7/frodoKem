/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! ## Usage
//!
//!
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_parens,
    unused_qualifications
)]

mod error;
mod models;
mod params;
mod traits;

pub use error::*;
pub use models::*;
pub use params::*;
pub use traits::*;

use rand_core::CryptoRngCore;
use sha3::digest::{ExtendableOutput, ExtendableOutputReset, Update, XofReader};
use std::{
    io::{Cursor, Write},
    marker::PhantomData,
};
use zeroize::Zeroize;

#[cfg(feature = "frodo640aes")]
/// The FrodoKEM-640-AES algorithm
pub const FRODO_KEM_640_AES: FrodoKem<ExpandSeedAes, CdfSampler> = FrodoKem {
    params: FRODO_640_PARAMS,
    _generics: PhantomData,
};
#[cfg(feature = "frodo976aes")]
/// The FrodoKEM-976-AES algorithm
pub const FRODO_KEM_976_AES: FrodoKem<ExpandSeedAes, CdfSampler> = FrodoKem {
    params: FRODO_976_PARAMS,
    _generics: PhantomData,
};

#[cfg(feature = "frodo1344aes")]
/// The FrodoKEM-1344-AES algorithm
pub const FRODO_KEM_1344_AES: FrodoKem<ExpandSeedAes, CdfSampler> = FrodoKem {
    params: FRODO_1344_PARAMS,
    _generics: PhantomData,
};
#[cfg(feature = "frodo640shake")]
/// The FrodoKEM-640-SHAKE algorithm
pub const FRODO_KEM_640_SHAKE: FrodoKem<ExpandSeedShake, CdfSampler> = FrodoKem {
    params: FRODO_640_PARAMS,
    _generics: PhantomData,
};
#[cfg(feature = "frodo976shake")]
/// The FrodoKEM-976-SHAKE algorithm
pub const FRODO_KEM_976_SHAKE: FrodoKem<ExpandSeedShake, CdfSampler> = FrodoKem {
    params: FRODO_976_PARAMS,
    _generics: PhantomData,
};
#[cfg(feature = "frodo1344shake")]
/// The FrodoKEM-1344-SHAKE algorithm
pub const FRODO_KEM_1344_SHAKE: FrodoKem<ExpandSeedShake, CdfSampler> = FrodoKem {
    params: FRODO_1344_PARAMS,
    _generics: PhantomData,
};

/// The FrodoKEM struct
#[derive(Copy, Clone, Debug)]
pub struct FrodoKem<E: ExpandSeedA, S: NoiseSampler> {
    /// The parameters for the FrodoKEM
    params: Params,
    _generics: PhantomData<(E, S)>,
}

impl<E: ExpandSeedA, S: NoiseSampler> FrodoKem<E, S> {
    /// Create a new FrodoKEM instance
    pub const fn new(params: Params) -> Self {
        Self {
            params,
            _generics: PhantomData,
        }
    }

    /// Get the parameters for the FrodoKEM
    pub const fn params(&self) -> &Params {
        &self.params
    }

    /// Get the algorithm name
    pub fn algorithm(&self) -> String {
        format!("FrodoKEM-{}-{}", self.params.n, E::METHOD)
    }

    /// Generate a keypair
    ///
    /// See Algorithm 9 in specification
    pub fn generate_keypair(&self, mut rng: impl CryptoRngCore) -> (PublicKey, SecretKey) {
        // holds the secret value s, the seed for S and E,
        // and the seed for matrix A. Add seed_A to the public key
        let mut randomness = vec![0u8; 2 * self.params.bytes_pk_hash + self.params.bytes_seed_a];
        rng.fill_bytes(&mut randomness);

        let randomness_s = &randomness[..self.params.bytes_pk_hash];
        let randomness_seed_se =
            &randomness[self.params.bytes_pk_hash..2 * self.params.bytes_pk_hash];

        let mut shake = sha3::Shake256::default();
        shake.update(&randomness[2 * self.params.bytes_pk_hash..]);
        let mut pk_seed_a = shake.finalize_boxed_reset(self.params.bytes_seed_a);

        let mut shake_input_seed_se = vec![0x5F; 1 + self.params.bytes_pk_hash];
        shake_input_seed_se[1..].copy_from_slice(randomness_seed_se);
        shake.update(&shake_input_seed_se);
        let mut xof_reader = shake.finalize_xof_reset();

        let n_x_nbar = self.params.n * self.params.n_bar;

        let mut s_matrix = vec![0u16; 2 * n_x_nbar];
        let mut u16_bytes = [0u8; 2];
        for i in s_matrix.iter_mut() {
            xof_reader.read(&mut u16_bytes);
            *i = u16::from_le_bytes(u16_bytes);
        }
        S::sample(&self.params, &mut s_matrix[..n_x_nbar], n_x_nbar);
        S::sample(&self.params, &mut s_matrix[n_x_nbar..], n_x_nbar);

        let mut a_matrix = vec![0u16; n_x_nbar];
        E::expand_a(&self.params, &mut a_matrix, pk_seed_a.as_ref());

        let mut b_matrix = vec![0u16; n_x_nbar];
        self.mul_add_as_plus_e(
            &s_matrix[..n_x_nbar],
            &s_matrix[n_x_nbar..],
            &a_matrix,
            &mut b_matrix,
        );
        let mut pk = vec![0u8; self.params.public_key_length];
        pk[..self.params.bytes_seed_a].copy_from_slice(pk_seed_a.as_ref());
        self.pack(
            &b_matrix,
            self.params.log_q as u8,
            &mut pk[self.params.bytes_seed_a..],
        );

        let mut sk = vec![0u8; self.params.secret_key_length];
        let mut cursor = Cursor::new(&mut sk);
        cursor.write(randomness_s).expect("write s");
        cursor.write(pk.as_slice()).expect("write pk");

        for i in &s_matrix {
            cursor.write(&i.to_le_bytes()).expect("write s_matrix");
        }
        shake.update(&pk);
        cursor
            .write(shake.finalize_boxed(self.params.bytes_pk_hash).as_ref())
            .expect("write pk hash");

        b_matrix.zeroize();
        s_matrix.zeroize();
        randomness.zeroize();
        shake_input_seed_se.zeroize();
        pk_seed_a.zeroize();

        (PublicKey(pk), SecretKey(sk))
    }

    fn mul_add_as_plus_e(&self, s: &[u16], e: &[u16], a_matrix: &[u16], out: &mut [u16]) {
        debug_assert_eq!(out.len(), e.len());
        out.copy_from_slice(e);

        // Matrix multiplication-addition A*s + e
        for i in 0..self.params.n {
            for k in 0..self.params.n_bar {
                let mut sum = 0u16;
                for j in 0..self.params.n {
                    sum = sum.wrapping_add(
                        a_matrix[i * self.params.n + j].wrapping_mul(s[k * self.params.n_bar + j]),
                    );
                }
                out[i * self.params.n_bar + k] = out[i * self.params.n_bar + k].wrapping_add(sum);
            }
        }
    }

    fn pack(&self, input: &[u16], lsb: u8, out: &mut [u8]) {
        // Pack the input u16 slice into a u8 output slice, copying lsb bits from each input element.
        // If input.len * lsb / 8 > out.len, only out.len * 8 bits are copied.

        let mut i = 0usize; // whole bytes already filled in
        let mut j = 0usize; // whole uint16_t already copied
        let mut w = 0u16; // the leftover, not yet copied
        let mut bits = 0u8; // the number of lsb in w

        while i < out.len() && (j < input.len() || ((j == input.len()) && (bits > 0))) {
            let mut b = 0u8; // bits in out[i] already filled in
            while b < 8 {
                let nbits = std::cmp::min(8 - b, bits);
                let mask = (1u16 << nbits).wrapping_sub(1);
                let t = u8::try_from((w >> (bits - nbits)) & mask).expect("to fit in u8"); // the bits to copy from w to out
                out[i] = out[i] + (t << (8 - b - nbits));
                b += nbits;
                bits -= nbits;
                w &= !(mask << bits); // not strictly necessary; mostly for debugging

                if bits == 0 {
                    if j < input.len() {
                        w = input[j];
                        bits = lsb;
                        j += 1;
                    } else {
                        break; // the input vector is exhausted
                    }
                }
            }
            if b == 8 {
                // out[i] is filled in
                i += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    #[test]
    fn compatibility() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let (our_pk, our_sk) = FRODO_KEM_640_AES.generate_keypair(rng);
    }
}
