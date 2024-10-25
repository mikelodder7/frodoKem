/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

use rand_core::CryptoRngCore;
use sha3::digest::{ExtendableOutput, ExtendableOutputReset, Update, XofReader};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

use crate::models::PublicKeyRef;
use crate::{Ciphertext, PublicKey, SecretKey, SharedSecret};

/// The FrodoKEM parameters
pub trait Params: Sized {
    /// The SHAKE method
    type Shake: Default + ExtendableOutput + ExtendableOutputReset + Update;
    /// The number of elements in the ring
    const N: usize;
    /// The number of rows in the matrix
    const N_BAR: usize = 8;
    const LOG_Q: usize;
    const EXTRACTED_BITS: usize;
    const STRIPE_STEP: usize = 8;
    const PARALLEL: usize = 4;
    const BYTES_SEED_A: usize = 16;
    const BYTES_PK_HASH: usize = Self::SHARED_SECRET_LENGTH;
    const CDF_TABLE: &'static [u16];
    const CLAIMED_NIST_LEVEL: usize;
    const SHARED_SECRET_LENGTH: usize;
    const BYTES_MU: usize = (Self::EXTRACTED_BITS * Self::N_BAR_X_N_BAR) / 8;
    /// = len(s) + len(seedSE) + len(z)
    const KEY_SEED_SIZE: usize = 2 * Self::SHARED_SECRET_LENGTH + Self::BYTES_SEED_A;
    const TWO_N: usize = 2 * Self::N;
    const TWO_PLUS_BYTES_SEED_A: usize = 2 + Self::BYTES_SEED_A;
    ///
    const N_X_N: usize = Self::N * Self::N;
    const N_X_N_BAR: usize = Self::N * Self::N_BAR;
    const N_BAR_X_N: usize = Self::N_BAR * Self::N;
    const N_BAR_X_N_BAR: usize = Self::N_BAR * Self::N_BAR;
    const TWO_N_X_N_BAR: usize = 2 * Self::N_X_N_BAR;
    const EXTRACTED_BITS_MASK: u16 = (1 << Self::EXTRACTED_BITS) - 1;
    const SHIFT: usize = Self::LOG_Q - Self::EXTRACTED_BITS;
    const Q: usize = 1 << Self::LOG_Q;
    /// The mask for the modulus
    const Q_MASK: u16 = (Self::Q - 1) as u16;
    const LOG_Q_X_N_X_N_BAR_DIV_8: usize = (Self::LOG_Q * Self::N_X_N_BAR) / 8;
    /// The public key length
    const PUBLIC_KEY_LENGTH: usize = Self::LOG_Q_X_N_X_N_BAR_DIV_8 + Self::BYTES_SEED_A;
    /// The secret key length
    const SECRET_KEY_LENGTH: usize = Self::PUBLIC_KEY_LENGTH
        + Self::TWO_N_X_N_BAR
        + Self::BYTES_PK_HASH
        + Self::SHARED_SECRET_LENGTH;
    /// The ciphertext length
    const CIPHERTEXT_LENGTH: usize =
        Self::LOG_Q_X_N_X_N_BAR_DIV_8 + (Self::LOG_Q * Self::N_BAR_X_N_BAR) / 8;
}

pub trait Sample {
    fn sample(s: &mut [u16]);
}

pub trait Expanded {
    /// The method used to expand the seed
    const METHOD: &'static str;
    /// Expand the seed to produce the matrix A
    /// Generate matrix A (N x N) column-wise
    fn expand_a(seed_a: &[u8], a: &mut [u16]);
}

pub trait Kem: Params + Expanded + Sample {
    /// Get the algorithm name
    fn algorithm(&self) -> String {
        format!("FrodoKEM-{}-{}", Self::N, Self::METHOD)
    }

    /// Generate a keypair
    ///
    /// See Algorithm 9 in specification
    fn generate_keypair(&self, mut rng: impl CryptoRngCore) -> (PublicKey<Self>, SecretKey<Self>) {
        let mut sk = SecretKey::default();
        let mut pk = PublicKey::default();
        let mut randomness = vec![0u8; Self::KEY_SEED_SIZE];
        rng.fill_bytes(&mut randomness);

        sk.random_s_mut()
            .copy_from_slice(&randomness[..Self::SHARED_SECRET_LENGTH]);
        let randomness_seed_se =
            &randomness[Self::SHARED_SECRET_LENGTH..2 * Self::SHARED_SECRET_LENGTH];
        let randomness_z = &randomness[2 * Self::SHARED_SECRET_LENGTH..];

        let mut shake = Self::Shake::default();
        shake.update(randomness_z);
        shake.finalize_xof_reset_into(pk.seed_a_mut());

        shake.update(&[0x5F]);
        shake.update(&randomness_seed_se);
        let mut shake_reader = shake.finalize_xof_reset();
        let mut u16_buffer = [0u8; 2];

        // 1st half is matrix S
        // 2nd half is matrix E
        let mut bytes_se = vec![0u16; Self::TWO_N_X_N_BAR];
        for b in bytes_se.iter_mut() {
            shake_reader.read(&mut u16_buffer);
            *b = u16::from_le_bytes(u16_buffer);
        }

        Self::sample(&mut bytes_se[..Self::N_X_N_BAR]);
        Self::sample(&mut bytes_se[Self::N_X_N_BAR..]);

        let mut a_matrix = vec![0u16; Self::N_X_N];
        Self::expand_a(pk.seed_a(), &mut a_matrix);

        let mut matrix_b = vec![0u16; Self::N_X_N_BAR];
        self.mul_add_as_plus_e(
            &a_matrix,
            &bytes_se[..Self::N_X_N_BAR],
            &bytes_se[Self::N_X_N_BAR..],
            &mut matrix_b,
        );

        self.pack(&matrix_b, pk.matrix_b_mut());

        {
            let matrix_s = sk.matrix_s_mut();
            for (i, b) in bytes_se[..Self::N_X_N_BAR].iter().enumerate() {
                let bb = b.to_le_bytes();
                matrix_s[i * 2] = bb[0];
                matrix_s[i * 2 + 1] = bb[1];
            }
        }

        shake.update(&pk.0);
        shake.finalize_xof_into(sk.hpk_mut());
        sk.public_key_mut().copy_from_slice(&pk.0);

        bytes_se.zeroize();
        randomness.zeroize();
        u16_buffer.zeroize();

        (pk, sk)
    }

    fn encapsulate(
        &self,
        public_key: &PublicKey<Self>,
        mut rng: impl CryptoRngCore,
    ) -> (Ciphertext<Self>, SharedSecret<Self>) {
        let mut ct = Ciphertext::default();
        let mut ss = SharedSecret::default();

        let mut shake = Self::Shake::default();
        let mut g2_in = vec![0u8; Self::BYTES_PK_HASH + Self::BYTES_MU];

        shake.update(&public_key.0);
        shake.finalize_xof_reset_into(&mut g2_in[..Self::BYTES_PK_HASH]);
        rng.fill_bytes(&mut g2_in[Self::BYTES_PK_HASH..]);
        let mut g2_out = vec![0u8; 2 * Self::SHARED_SECRET_LENGTH];
        shake.update(&g2_in);
        shake.finalize_xof_reset_into(&mut g2_out);

        let mut sp = vec![0u16; (2 * Self::N + Self::N_BAR) * Self::N_BAR];
        shake.update(&[0x96]);
        shake.update(&g2_out[..Self::SHARED_SECRET_LENGTH]);
        let mut shake_reader = shake.finalize_xof_reset();
        let mut u16_buffer = [0u8; 2];
        for b in sp.iter_mut() {
            shake_reader.read(&mut u16_buffer);
            *b = u16::from_le_bytes(u16_buffer);
        }

        Self::sample(&mut sp[..Self::N_X_N_BAR]);
        Self::sample(&mut sp[Self::N_X_N_BAR..2 * Self::N_X_N_BAR]);
        Self::sample(&mut sp[2 * Self::N_X_N_BAR..]);

        let s = &sp[..Self::N_X_N_BAR];
        let ep = &sp[Self::N_X_N_BAR..2 * Self::N_X_N_BAR];
        let epp = &sp[2 * Self::N_X_N_BAR..];

        let mut matrix_a = vec![0u16; Self::N_X_N];
        Self::expand_a(public_key.seed_a(), &mut matrix_a);

        let mut matrix_b = vec![0u16; Self::N_X_N_BAR];
        self.mul_add_sa_plus_e(&s, &matrix_a, &ep, &mut matrix_b);

        self.pack(&matrix_b, ct.c1_mut());
        let mut pk_matrix_b = vec![0u16; Self::N_X_N_BAR];
        self.unpack(public_key.matrix_b(), &mut pk_matrix_b);

        let mut matrix_v = vec![0u16; Self::N_BAR_X_N_BAR];
        self.mul_add_sb_plus_e(&s, &pk_matrix_b, &epp, &mut matrix_v);

        let mut matrix_c = vec![0u16; Self::N_BAR_X_N_BAR];

        self.encode_message(&g2_in[Self::BYTES_PK_HASH..], &mut matrix_c);
        self.add(&matrix_v, &mut matrix_c);
        self.pack(&matrix_c, ct.c2_mut());

        shake.update(&ct.0);
        shake.update(&g2_out[Self::SHARED_SECRET_LENGTH..]);
        shake.finalize_xof_into(&mut ss.0);

        matrix_v.zeroize();
        sp.zeroize();
        g2_in[Self::BYTES_PK_HASH..].zeroize();
        g2_out.zeroize();

        (ct, ss)
    }

    fn decapsulate(
        &self,
        ciphertext: &Ciphertext<Self>,
        secret_key: &SecretKey<Self>,
    ) -> SharedSecret<Self> {
        let mut ss = SharedSecret::default();
        let mut matrix_s = vec![0u16; Self::N_X_N_BAR];
        let pk =
            PublicKeyRef::<Self>::from_slice(secret_key.public_key()).expect("Invalid public key");

        for (i, b) in matrix_s.iter_mut().enumerate() {
            let bb = [
                secret_key.matrix_s()[i * 2],
                secret_key.matrix_s()[i * 2 + 1],
            ];
            *b = u16::from_le_bytes(bb);
        }

        let mut matrix_bp = vec![0u16; Self::N_X_N_BAR];
        self.unpack(ciphertext.c1(), &mut matrix_bp);

        let mut matrix_c = vec![0u16; Self::N_BAR_X_N_BAR];
        self.unpack(ciphertext.c2(), &mut matrix_c);

        // W = C - Bp*S mod q
        let mut matrix_w = vec![0u16; Self::N_BAR_X_N_BAR];
        self.mul_bs(&matrix_bp, &matrix_s, &mut matrix_w);
        self.sub(&matrix_c, &mut matrix_w);

        let mut g2_in = vec![0u8; Self::BYTES_PK_HASH + Self::BYTES_MU];
        let mut g2_out = vec![0u8; 2 * Self::SHARED_SECRET_LENGTH];

        g2_in[..Self::BYTES_PK_HASH].copy_from_slice(secret_key.hpk());
        // µ'
        self.decode_message(&matrix_w, &mut g2_in[Self::BYTES_PK_HASH..]);

        let mut shake = Self::Shake::default();
        shake.update(&g2_in);
        shake.finalize_xof_reset_into(&mut g2_out);

        let mut sp = vec![0u16; (2 * Self::N + Self::N_BAR) * Self::N_BAR];
        shake.update(&[0x96]);
        shake.update(&g2_out[..Self::SHARED_SECRET_LENGTH]);
        let mut shake_reader = shake.finalize_xof_reset();
        let mut u16_buffer = [0u8; 2];
        for b in sp.iter_mut() {
            shake_reader.read(&mut u16_buffer);
            *b = u16::from_le_bytes(u16_buffer);
        }

        Self::sample(&mut sp[..Self::N_X_N_BAR]);
        Self::sample(&mut sp[Self::N_X_N_BAR..2 * Self::N_X_N_BAR]);
        Self::sample(&mut sp[2 * Self::N_X_N_BAR..]);

        let s = &sp[..Self::N_X_N_BAR];
        let ep = &sp[Self::N_X_N_BAR..2 * Self::N_X_N_BAR];
        let epp = &sp[2 * Self::N_X_N_BAR..];

        let mut matrix_a = vec![0u16; Self::N_X_N];
        Self::expand_a(&pk.seed_a(), &mut matrix_a);

        let mut matrix_bpp = vec![0u16; Self::N_X_N_BAR];
        self.mul_add_sa_plus_e(&s, &matrix_a, &ep, &mut matrix_bpp);
        // BB mod q
        matrix_bpp.iter_mut().for_each(|b| *b &= Self::Q_MASK);

        let mut matrix_b = vec![0u16; Self::N_X_N_BAR];
        self.unpack(&pk.matrix_b(), &mut matrix_b);

        // W = Sp*B + Epp
        self.mul_add_sb_plus_e(&s, &matrix_b, &epp, &mut matrix_w);

        // CC = W + enc(µ') mod q
        let mut matrix_cc = vec![0u16; Self::N_BAR_X_N_BAR];
        self.encode_message(&g2_in[Self::BYTES_PK_HASH..], &mut matrix_cc);
        self.add(&matrix_w, &mut matrix_cc);

        shake.update(&ciphertext.0);
        // If (Bp == BBp & C == CC) then ss = F(ct || k'), else ss = F(ct || s)
        // Needs to avoid branching on secret data as per:
        //     Qian Guo, Thomas Johansson, Alexander Nilsson. A key-recovery timing attack on post-quantum
        //     primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM. In CRYPTO 2020.
        let choice =
            self.ct_verify(&matrix_bp, &matrix_bpp) & self.ct_verify(&matrix_c, &matrix_cc);

        let mut fin_k = vec![0u8; Self::SHARED_SECRET_LENGTH];
        /// Take k if choice == 0, otherwise take s
        self.ct_select(
            choice,
            &g2_out[Self::SHARED_SECRET_LENGTH..],
            secret_key.random_s(),
            &mut fin_k,
        );

        shake.update(&fin_k);
        shake.finalize_xof_into(&mut ss.0);

        ss
    }

    fn mul_add_as_plus_e(&self, a: &[u16], s: &[u16], e: &[u16], b: &mut [u16]) {
        debug_assert_eq!(a.len(), Self::N_X_N);
        debug_assert_eq!(s.len(), Self::N_X_N_BAR);
        debug_assert_eq!(e.len(), Self::N_X_N_BAR);
        debug_assert_eq!(b.len(), Self::N_X_N_BAR);

        for i in 0..Self::N {
            let i_bar = i * Self::N_BAR;
            let i_n = i * Self::N;
            for k in 0..Self::N_BAR {
                let mut sum = e[i_bar + k];
                for j in 0..Self::N {
                    sum = sum.wrapping_add(a[i_n + j].wrapping_mul(s[k * Self::N + j]));
                }
                b[i_bar + k] = b[i_bar + k].wrapping_add(sum);
            }
        }
    }

    fn mul_add_sa_plus_e(&self, s: &[u16], a: &[u16], e: &[u16], out: &mut [u16]) {
        debug_assert_eq!(a.len(), Self::N_X_N);
        debug_assert_eq!(s.len(), Self::N_X_N_BAR);
        debug_assert_eq!(e.len(), Self::N_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N);

        for i in 0..Self::N {
            for k in 0..Self::N_BAR {
                let mut sum = e[k * Self::N + i];
                let k_n = k * Self::N;
                for j in 0..Self::N {
                    sum = sum.wrapping_add(a[j * Self::N + i].wrapping_mul(s[k_n + j]));
                }
                out[k_n + i] = out[k_n + i].wrapping_add(sum);
            }
        }
    }

    /// Multiply by s on the left
    /// Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
    /// Output: out = s*b + e (N_BAR x N_BAR)
    fn mul_add_sb_plus_e(&self, s: &[u16], b: &[u16], e: &[u16], out: &mut [u16]) {
        debug_assert_eq!(b.len(), Self::N_X_N_BAR);
        debug_assert_eq!(s.len(), Self::N_BAR_X_N);
        debug_assert_eq!(e.len(), Self::N_BAR_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N_BAR);

        for k in 0..Self::N_BAR {
            let k_n = k * Self::N;
            let k_bar = k * Self::N_BAR;
            for i in 0..Self::N_BAR {
                let mut sum = e[k_bar + i];
                for j in 0..Self::N {
                    sum = sum.wrapping_add(s[k_n + j].wrapping_mul(b[j * Self::N_BAR + i]));
                }
                out[k_bar + i] = sum & Self::Q_MASK;
            }
        }
    }

    fn mul_bs(&self, b: &[u16], s: &[u16], out: &mut [u16]) {
        debug_assert_eq!(b.len(), Self::N_BAR_X_N);
        debug_assert_eq!(s.len(), Self::N_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N_BAR);

        for i in 0..Self::N_BAR {
            let i_n = i * Self::N;
            let i_bar = i * Self::N_BAR;
            for j in 0..Self::N_BAR {
                let mut sum = 0u16;
                for k in 0..Self::N {
                    sum = sum.wrapping_add(b[i_n + k].wrapping_mul(s[j * Self::N + k]));
                }
                out[i_bar + j] = sum & Self::Q_MASK;
            }
        }
    }

    fn add(&self, rhs: &[u16], out: &mut [u16]) {
        debug_assert_eq!(rhs.len(), Self::N_BAR_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N_BAR);
        for i in 0..Self::N_BAR_X_N_BAR {
            out[i] = out[i].wrapping_add(rhs[i]) & Self::Q_MASK;
        }
    }

    fn sub(&self, lhs: &[u16], out: &mut [u16]) {
        debug_assert_eq!(lhs.len(), Self::N_BAR_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N_BAR);
        for i in 0..Self::N_BAR_X_N_BAR {
            out[i] = lhs[i].wrapping_sub(out[i]) & Self::Q_MASK;
        }
    }

    fn encode_message(&self, msg: &[u8], output: &mut [u16]) {
        debug_assert_eq!(msg.len(), Self::SHARED_SECRET_LENGTH);
        debug_assert_eq!(output.len(), Self::N_BAR_X_N_BAR);

        let j_limit = 16 / Self::EXTRACTED_BITS;
        let mut pos = 0;
        let mut i = 0;
        let mut ii = 0;

        while ii < msg.len() {
            let mut input = u16::from_le_bytes([msg[ii], msg[ii + 1]]);
            for _ in 0..j_limit {
                output[pos] = (input & Self::EXTRACTED_BITS_MASK) << Self::SHIFT;
                pos += 1;

                input >>= Self::EXTRACTED_BITS;
            }

            i += 1;
            ii = i * 2;
        }
    }

    fn decode_message(&self, input: &[u16], output: &mut [u8]) {
        debug_assert_eq!(input.len(), Self::N_BAR_X_N_BAR);
        debug_assert_eq!(output.len(), Self::SHARED_SECRET_LENGTH);

        let add = 1u16 << (Self::SHIFT - 1);
        let j_limit = 8 / Self::EXTRACTED_BITS;

        let mut pos = 0;
        let out_len = output.len();
        for i in 0..out_len {
            for j in 0..j_limit {
                let mut t = (input[pos] & Self::Q_MASK) + add;
                t >>= Self::SHIFT;
                t &= Self::EXTRACTED_BITS_MASK;
                output[i] |= (t as u8) << (j * Self::EXTRACTED_BITS);
                pos += 1;
            }
        }
    }

    fn pack(&self, input: &[u16], output: &mut [u8]) {
        let mut i = 0;
        let mut ii = 0;
        let mut j = 0;

        while ii < input.len() {
            let in0 = input[ii] & Self::Q_MASK;
            let in1 = input[ii + 1] & Self::Q_MASK;
            let in2 = input[ii + 2] & Self::Q_MASK;
            let in3 = input[ii + 3] & Self::Q_MASK;
            let in4 = input[ii + 4] & Self::Q_MASK;
            let in5 = input[ii + 5] & Self::Q_MASK;
            let in6 = input[ii + 6] & Self::Q_MASK;
            let in7 = input[ii + 7] & Self::Q_MASK;

            output[j] |= (in0 >> 7) as u8;
            output[j + 1] = (((in0 & 0x7F) as u8) << 1) | ((in1 >> 14) as u8);

            output[j + 2] = (in1 >> 6) as u8;
            output[j + 3] = (((in1 & 0x3F) as u8) << 2) | ((in2 >> 13) as u8);

            output[j + 4] = (in2 >> 5) as u8;
            output[j + 5] = (((in2 & 0x1F) as u8) << 3) | ((in3 >> 12) as u8);

            output[j + 6] = (in3 >> 4) as u8;
            output[j + 7] = (((in3 & 0x0F) as u8) << 4) | ((in4 >> 11) as u8);

            output[j + 8] = (in4 >> 3) as u8;
            output[j + 9] = (((in4 & 0x07) as u8) << 5) | ((in5 >> 10) as u8);

            output[j + 10] = (in5 >> 2) as u8;
            output[j + 11] = (((in5 & 0x03) as u8) << 6) | ((in6 >> 9) as u8);

            output[j + 12] = (in6 >> 1) as u8;
            output[j + 13] = (((in6 & 0x01) as u8) << 7) | ((in7 >> 8) as u8);

            output[j + 14] = in7 as u8;

            j += 15;
            i += 1;
            ii = i * 8;
        }
    }

    fn unpack(&self, input: &[u8], output: &mut [u16]) {
        let mut i = 0;
        let mut ii = 0;
        let mut j = 0;

        while ii < input.len() {
            let in0 = input[ii];
            let in1 = input[ii + 1];
            let in2 = input[ii + 2];
            let in3 = input[ii + 3];
            let in4 = input[ii + 4];
            let in5 = input[ii + 5];
            let in6 = input[ii + 6];
            let in7 = input[ii + 7];
            let in8 = input[ii + 8];
            let in9 = input[ii + 9];
            let in10 = input[ii + 10];
            let in11 = input[ii + 11];
            let in12 = input[ii + 12];
            let in13 = input[ii + 13];
            let in14 = input[ii + 14];

            output[j] = ((in0 as u16) << 7) | (((in1 & 0xFE) as u16) >> 1);
            output[j + 1] =
                (((in1 & 0x01) as u16) << 14) | ((in2 as u16) << 6) | (((in3 & 0xFC) as u16) >> 2);
            output[j + 2] =
                (((in3 & 0x03) as u16) << 13) | ((in4 as u16) << 5) | (((in5 & 0xF8) as u16) >> 3);
            output[j + 3] =
                (((in5 & 0x07) as u16) << 12) | ((in6 as u16) << 4) | (((in7 & 0xF0) as u16) >> 4);
            output[j + 4] =
                (((in7 & 0x0F) as u16) << 11) | ((in8 as u16) << 3) | (((in9 & 0xE0) as u16) >> 5);
            output[j + 5] = (((in9 & 0x1F) as u16) << 10)
                | ((in10 as u16) << 2)
                | (((in11 & 0xC0) as u16) >> 6);
            output[j + 6] = (((in11 & 0x3F) as u16) << 9)
                | ((in12 as u16) << 1)
                | (((in13 & 0x80) as u16) >> 7);
            output[j + 7] = (((in13 & 0x7F) as u16) << 8) | (in14 as u16);

            j += 8;
            i += 1;
            ii = i * 15;
        }
    }

    fn ct_verify(&self, a: &[u16], b: &[u16]) -> Choice {
        let mut choice = 0;

        for i in 0..a.len() {
            choice |= a[i] ^ b[i];
        }

        choice = ((choice | choice.wrapping_neg()) >> 15) + 1;
        Choice::from(choice as u8)
    }

    fn ct_select(&self, choice: Choice, a: &[u8], b: &[u8], out: &mut [u8]) {
        for i in 0..a.len() {
            out[i] = u8::conditional_select(&b[i], &a[i], choice);
        }
    }
}
