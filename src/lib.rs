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

#[cfg(feature = "frodo640aes")]
/// The FrodoKEM-640-AES algorithm
pub type FrodoKem640Aes = FrodoKem<Frodo640, FrodoAes<Frodo640>, FrodoCdfSample<Frodo640>>;

#[cfg(feature = "frodo976aes")]
/// The FrodoKEM-976-AES algorithm
pub type FrodoKem976Aes = FrodoKem<Frodo976, FrodoAes<Frodo976>, FrodoCdfSample<Frodo976>>;

#[cfg(feature = "frodo1344aes")]
/// The FrodoKEM-1344-AES algorithm
pub type FrodoKem1344Aes = FrodoKem<Frodo1344, FrodoAes<Frodo1344>, FrodoCdfSample<Frodo1344>>;

#[cfg(feature = "frodo640shake")]
/// The FrodoKEM-640-SHAKE algorithm
pub type FrodoKem640Shake = FrodoKem<Frodo640, FrodoShake<Frodo640>, FrodoCdfSample<Frodo640>>;

#[cfg(feature = "frodo976shake")]
/// The FrodoKEM-976-SHAKE algorithm
pub type FrodoKem976Shake = FrodoKem<Frodo976, FrodoShake<Frodo976>, FrodoCdfSample<Frodo976>>;

#[cfg(feature = "frodo1344shake")]
/// The FrodoKEM-1344-SHAKE algorithm
pub type FrodoKem1344Shake = FrodoKem<Frodo1344, FrodoShake<Frodo1344>, FrodoCdfSample<Frodo1344>>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;
    use rstest::*;

    #[test]
    fn parameter_calculations() {
        assert_eq!(FrodoKem640Shake::N, 640);
        assert_eq!(FrodoKem640Shake::N_BAR, 8);
        assert_eq!(FrodoKem640Shake::LOG_Q, 15);
        assert_eq!(FrodoKem640Shake::EXTRACTED_BITS, 2);
        assert_eq!(FrodoKem640Shake::STRIPE_STEP, 8);
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
    fn shake976_compatibility() {
        let safe_kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem976Shake).unwrap();
        let (their_pk, their_sk) = safe_kem.keypair().unwrap();
        let my_pk = PublicKey::<FrodoKem976Shake>::from_slice(their_pk.as_ref()).unwrap();
        let my_sk = SecretKey::<FrodoKem976Shake>::from_slice(their_sk.as_ref()).unwrap();

        let kem = FrodoKem976Shake::default();

        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);

        let (my_ct, my_ess) = kem.encapsulate(&my_pk, &mut rng);
        let my_ss = kem.decapsulate(&my_ct, &my_sk);
        assert_eq!(my_ess.as_ref(), my_ss.as_ref());

        let their_ct = safe_kem.ciphertext_from_bytes(my_ct.as_ref()).unwrap();
        let their_ss = safe_kem.decapsulate(&their_sk, &their_ct).unwrap();
        assert_eq!(my_ess.as_ref(), their_ss.as_ref());
    }

    #[rstest]
    #[case::aes640(FrodoKem640Aes::default(), safe_oqs::kem::Algorithm::FrodoKem640Aes)]
    #[case::shake640(
        FrodoKem640Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem640Shake
    )]
    #[case::aes976(FrodoKem976Aes::default(), safe_oqs::kem::Algorithm::FrodoKem976Aes)]
    #[case::shake976(
        FrodoKem976Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem976Shake
    )]
    #[case::aes1344(FrodoKem1344Aes::default(), safe_oqs::kem::Algorithm::FrodoKem1344Aes)]
    #[case::shake1344(
        FrodoKem1344Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem1344Shake
    )]
    fn generate_keypair_compatibility<F: Kem>(
        #[case] kem: F,
        #[case] alg: safe_oqs::kem::Algorithm,
    ) {
        let rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let (our_pk, our_sk) = kem.generate_keypair(rng);
        let kem = safe_oqs::kem::Kem::new(alg).unwrap();
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

    #[rstest]
    #[case::aes640(FrodoKem640Aes::default(), safe_oqs::kem::Algorithm::FrodoKem640Aes)]
    #[case::shake640(
        FrodoKem640Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem640Shake
    )]
    #[case::aes976(FrodoKem976Aes::default(), safe_oqs::kem::Algorithm::FrodoKem976Aes)]
    #[case::shake976(
        FrodoKem976Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem976Shake
    )]
    #[case::aes1344(FrodoKem1344Aes::default(), safe_oqs::kem::Algorithm::FrodoKem1344Aes)]
    #[case::shake1344(
        FrodoKem1344Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem1344Shake
    )]
    fn encapsulate_compatibility<F: Kem>(#[case] kem: F, #[case] alg: safe_oqs::kem::Algorithm) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let (our_pk, our_sk) = kem.generate_keypair(&mut rng);
        let safe_kem = safe_oqs::kem::Kem::new(alg).unwrap();

        let opt_sk = safe_kem.secret_key_from_bytes(&our_sk.0);
        assert!(opt_sk.is_some());

        let their_sk = opt_sk.unwrap();

        let (our_ciphertext, our_ss) = kem.encapsulate(&our_pk, &mut rng);

        let opt_ct = safe_kem.ciphertext_from_bytes(&our_ciphertext.0);
        assert!(opt_ct.is_some());
        let ct = opt_ct.unwrap();
        let res_ss = safe_kem.decapsulate(&their_sk, &ct);
        assert!(res_ss.is_ok());
        let their = res_ss.unwrap();
        assert_eq!(our_ss.as_ref(), their.as_ref());
    }

    #[rstest]
    #[case::aes640(FrodoKem640Aes::default(), safe_oqs::kem::Algorithm::FrodoKem640Aes)]
    #[case::shake640(
        FrodoKem640Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem640Shake
    )]
    #[case::aes976(FrodoKem976Aes::default(), safe_oqs::kem::Algorithm::FrodoKem976Aes)]
    #[case::shake976(
        FrodoKem976Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem976Shake
    )]
    #[case::aes1344(FrodoKem1344Aes::default(), safe_oqs::kem::Algorithm::FrodoKem1344Aes)]
    #[case::shake1344(
        FrodoKem1344Shake::default(),
        safe_oqs::kem::Algorithm::FrodoKem1344Shake
    )]
    fn decapsulate_compatibility<F: Kem>(#[case] kem: F, #[case] alg: safe_oqs::kem::Algorithm) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let (our_pk, our_sk) = kem.generate_keypair(&mut rng);
        let safe_kem = safe_oqs::kem::Kem::new(alg).unwrap();

        let opt_pk = safe_kem.public_key_from_bytes(&our_pk.0);
        assert!(opt_pk.is_some());
        let their_pk = opt_pk.unwrap();
        let opt_sk = safe_kem.secret_key_from_bytes(&our_sk.0);
        assert!(opt_sk.is_some());
        let their_sk = opt_sk.unwrap();

        let (our_ciphertext, our_ss) = kem.encapsulate(&our_pk, &mut rng);

        let opt_ss = kem.decapsulate(&our_ciphertext, &our_sk);
        assert_eq!(opt_ss.as_ref(), our_ss.as_ref());

        let (their_ct, their_ss) = safe_kem.encapsulate(&their_pk).unwrap();
        let res_my_ciphertext = Ciphertext::from_slice(their_ct.as_ref());
        assert!(res_my_ciphertext.is_ok());
        let my_ciphertext = res_my_ciphertext.unwrap();
        let my_ss = kem.decapsulate(&my_ciphertext, &our_sk);
        assert_eq!(my_ss.as_ref(), their_ss.as_ref());
    }
}