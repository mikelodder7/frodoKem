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
mod traits;

pub use error::*;
pub use models::*;
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
pub type FrodoKem640Aes = FrodoKem<Frodo640, FrodoAes<Frodo640>, FrodoCdfSample<Frodo640>>;

// #[cfg(feature = "frodo976aes")]
// /// The FrodoKEM-976-AES algorithm
// pub const FRODO_KEM_976_AES: FrodoKem<ExpandSeedAes, CdfSampler> = FrodoKem {
//     params: FRODO_976_PARAMS,
//     _generics: PhantomData,
// };
//
// #[cfg(feature = "frodo1344aes")]
// /// The FrodoKEM-1344-AES algorithm
// pub const FRODO_KEM_1344_AES: FrodoKem<ExpandSeedAes, CdfSampler> = FrodoKem {
//     params: FRODO_1344_PARAMS,
//     _generics: PhantomData,
// };
#[cfg(feature = "frodo640shake")]
/// The FrodoKEM-640-SHAKE algorithm
pub type FrodoKem640Shake = FrodoKem<Frodo640, FrodoShake<Frodo640>, FrodoCdfSample<Frodo640>>;

// #[cfg(feature = "frodo976shake")]
// /// The FrodoKEM-976-SHAKE algorithm
// pub const FRODO_KEM_976_SHAKE: FrodoKem<ExpandSeedShake, CdfSampler> = FrodoKem {
//     params: FRODO_976_PARAMS,
//     _generics: PhantomData,
// };
// #[cfg(feature = "frodo1344shake")]
// /// The FrodoKEM-1344-SHAKE algorithm
// pub const FRODO_KEM_1344_SHAKE: FrodoKem<ExpandSeedShake, CdfSampler> = FrodoKem {
//     params: FRODO_1344_PARAMS,
//     _generics: PhantomData,
// };

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    #[test]
    fn parameter_calculations() {
        assert_eq!(FrodoKem640Shake::N, 640);
        assert_eq!(FrodoKem640Shake::N_BAR, 8);
        assert_eq!(FrodoKem640Shake::LOG_Q, 15);
        assert_eq!(FrodoKem640Shake::EXTRACTED_BITS, 2);
        assert_eq!(FrodoKem640Shake::STRIPE_STEP, 8);
        assert_eq!(FrodoKem640Shake::PARALLEL, 4);
        assert_eq!(FrodoKem640Shake::BYTES_SEED_A, 16);
        assert_eq!(FrodoKem640Shake::BYTES_MU, 16);
        assert_eq!(FrodoKem640Shake::BYTES_PK_HASH, 16);
        assert_eq!(
            FrodoKem640Shake::CDF_TABLE,
            &[
                4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766,
                32767
            ]
        );
        assert_eq!(FrodoKem640Shake::CLAIMED_NIST_LEVEL, 1);
        assert_eq!(FrodoKem640Shake::SHARED_SECRET_LENGTH, 16);
        assert_eq!(FrodoKem640Shake::METHOD, "SHAKE");
        assert_eq!(FrodoKem640Shake::KEY_SEED_SIZE, 48);
        assert_eq!(FrodoKem640Shake::TWO_N, 1280);
        assert_eq!(FrodoKem640Shake::TWO_PLUS_BYTES_SEED_A, 18);
        assert_eq!(FrodoKem640Shake::N_X_N, 409600);
        assert_eq!(FrodoKem640Shake::N_X_N_BAR, 5120);
        assert_eq!(FrodoKem640Shake::N_BAR_X_N, 5120);
        assert_eq!(FrodoKem640Shake::N_BAR_X_N_BAR, 64);
        assert_eq!(FrodoKem640Shake::TWO_N_X_N_BAR, 10240);
        assert_eq!(FrodoKem640Shake::EXTRACTED_BITS_MASK, 3);
        assert_eq!(FrodoKem640Shake::SHIFT, 13);
        assert_eq!(FrodoKem640Shake::Q, 0x8000);
        assert_eq!(FrodoKem640Shake::Q_MASK, 0x7FFF);
        assert_eq!(FrodoKem640Shake::PUBLIC_KEY_LENGTH, 9616);
        assert_eq!(FrodoKem640Shake::SECRET_KEY_LENGTH, 19888);
        assert_eq!(FrodoKem640Shake::CIPHERTEXT_LENGTH, 9720);
    }

    #[test]
    fn shake_generate_keypair_compatibility() {
        let rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let kem = FrodoKem640Shake::default();
        let (our_pk, our_sk) = kem.generate_keypair(rng);
        let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem640Shake).unwrap();
        let opt_pk = kem.public_key_from_bytes(&our_pk.0);
        assert!(opt_pk.is_some());
        let opt_sk = kem.secret_key_from_bytes(&our_sk.0);
        assert!(opt_sk.is_some());

        let their_pk = opt_pk.unwrap();
        let their_sk = opt_sk.unwrap();

        let (ciphertext, pk_ss) = kem.encapsulate(&their_pk).unwrap();
        let sk_ss = kem.decapsulate(&their_sk, &ciphertext).unwrap();
        assert_eq!(pk_ss.as_ref(), sk_ss.as_ref());
    }

    #[test]
    fn aes_generate_keypair_compatibility() {
        let rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let kem = FrodoKem640Aes::default();
        let (our_pk, our_sk) = kem.generate_keypair(rng);
        let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem640Aes).unwrap();
        let opt_pk = kem.public_key_from_bytes(&our_pk.0);
        assert!(opt_pk.is_some());
        let opt_sk = kem.secret_key_from_bytes(&our_sk.0);
        assert!(opt_sk.is_some());

        let their_pk = opt_pk.unwrap();
        let their_sk = opt_sk.unwrap();

        let (ciphertext, pk_ss) = kem.encapsulate(&their_pk).unwrap();
        let sk_ss = kem.decapsulate(&their_sk, &ciphertext).unwrap();
        assert_eq!(pk_ss.as_ref(), sk_ss.as_ref());
    }
}
