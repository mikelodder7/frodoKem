/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::Params;

///  Generate matrix A (N x N) column-wise
pub trait ExpandSeedA {
    /// The method used to expand the seed
    const METHOD: &'static str;

    /// Expand the seed to produce the matrix A
    fn expand_a(params: &Params, a_matrix: &mut [u16], seed_a: &[u8]);
}

#[cfg(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes"
))]
/// Generate matrix A (N x N) column-wise using AES-128
///
/// See Algorithm 7
#[derive(Copy, Clone, Debug)]
pub struct ExpandSeedAes;

#[cfg(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes"
))]
impl ExpandSeedA for ExpandSeedAes {
    const METHOD: &'static str = "Aes";

    fn expand_a(params: &Params, a_matrix: &mut [u16], seed_a: &[u8]) {
        use aes::{
            cipher::{BlockEncrypt, KeyInit, KeySizeUser},
            Aes128Enc, Block,
        };

        assert_eq!(a_matrix.len(), params.n * params.n * 2);
        assert_eq!(seed_a.len(), params.bytes_seed_a);
        assert_eq!(seed_a.len(), <Aes128Enc as KeySizeUser>::key_size());
        let enc = Aes128Enc::new_from_slice(seed_a).expect("a valid key size of 16 bytes");
        let mut in_block = Block::default();
        let mut out_block = Block::default();

        for i in 0..params.n {
            let ii = i as u16;
            in_block[..2].copy_from_slice(&ii.to_le_bytes());
            let row = i * params.n;
            for j in (0..params.n).step_by(params.stripe_step) {
                let jj = j as u16;
                in_block[2..4].copy_from_slice(&jj.to_le_bytes());
                enc.encrypt_block_b2b(&in_block, &mut out_block);

                for k in 0..params.stripe_step {
                    a_matrix[row + j + k] =
                        u16::from_le_bytes([out_block[2 * k], out_block[2 * k + 1]]);
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
/// See Algorithm 8
#[derive(Copy, Clone, Debug)]
pub struct ExpandSeedShake;

#[cfg(any(
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake"
))]
impl ExpandSeedA for ExpandSeedShake {
    const METHOD: &'static str = "Shake";

    fn expand_a(params: &Params, a_matrix: &mut [u16], seed_a: &[u8]) {
        use sha3::digest::{ExtendableOutputReset, Update};

        assert_eq!(a_matrix.len(), params.n * params.n * 2);
        assert_eq!(seed_a.len(), params.bytes_seed_a);

        let mut in_bytes = vec![0u8; seed_a.len() + 2];
        in_bytes[2..].copy_from_slice(seed_a);

        let mut shake = sha3::Shake128::default();
        for i in 0..params.n {
            let ii = i as u16;
            in_bytes[..2].copy_from_slice(&ii.to_le_bytes());

            shake.update(&in_bytes);
            let out_bytes = shake.finalize_boxed_reset((16 * params.n) / 8);

            let row = i * params.n;
            for j in 0..params.n {
                a_matrix[row + j] = u16::from_le_bytes([out_bytes[2 * j], out_bytes[2 * j + 1]]);
            }
        }
    }
}

/// Fills vector `s` with `n` samples
/// from a noise distribution.
pub trait NoiseSampler {
    /// Sample `n` values from the noise distribution into `s`.
    fn sample(params: &Params, s: &mut [u16], n: usize);
}

/// A noise sampler that uses a CDF to sample values.
#[derive(Copy, Clone, Debug)]
pub struct CdfSampler;

impl NoiseSampler for CdfSampler {
    fn sample(params: &Params, s: &mut [u16], n: usize) {
        assert!(s.len() >= n);

        for i in 0..n {
            let mut sample = 0u16;
            let prnd = s[i] >> 1; // Drop the least significant bit
            let sign = s[i] & 1; // Get the least significant bit

            for j in 0..params.cdf_table.len() {
                sample = sample.wrapping_add(params.cdf_table[j].wrapping_sub(prnd) >> 15);
            }

            s[i] = (sign.wrapping_neg() ^ sample).wrapping_add(sign);
        }
    }
}
