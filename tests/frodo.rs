//! Tests for the FrodoKEM and FrodoKEM-640 schemes
use rstest::*;
use std::path::PathBuf;

mod rng;
mod rsp_reader;

use rng::*;
use rsp_reader::*;

#[rstest]
#[case::aes640("./tests/frodoKAT/PQCkemKAT_19888.rsp")]
#[case::shake640("./tests/frodoKAT/PQCkemKAT_19888_shake.rsp")]
#[case::aes976("./tests/frodoKAT/PQCkemKAT_31296.rsp")]
#[case::shake976("./tests/frodoKAT/PQCkemKAT_31296_shake.rsp")]
#[case::aes1344("./tests/frodoKAT/PQCkemKAT_43088.rsp")]
#[case::shake1344("./tests/frodoKAT/PQCkemKAT_43088_shake.rsp")]
#[case::ephemeral_aes640("./tests/efrodoKAT/PQCkemKAT_19888.rsp")]
#[case::ephemeral_shake640("./tests/efrodoKAT/PQCkemKAT_19888_shake.rsp")]
#[case::ephemeral_aes976("./tests/efrodoKAT/PQCkemKAT_31296.rsp")]
#[case::ephemeral_shake976("./tests/efrodoKAT/PQCkemKAT_31296_shake.rsp")]
#[case::ephemeral_aes1344("./tests/efrodoKAT/PQCkemKAT_43088.rsp")]
#[case::ephemeral_shake1344("./tests/efrodoKAT/PQCkemKAT_43088_shake.rsp")]
fn test_vector(#[case] path: &str) {
    let path = PathBuf::from(path);
    let rsp_reader = RspReader::new(path);
    let mut rng = AesCtrDrbg::default();
    let mut count = 0;

    for rsp_data in rsp_reader {
        count += 1;
        println!("{} Test {}", rsp_data.scheme, rsp_data.count + 1);
        rng.reseed(&rsp_data.seed);
        let (pk, sk) = rsp_data.scheme.generate_keypair(&mut rng);
        assert_eq!(pk, rsp_data.pk);
        assert_eq!(sk, rsp_data.sk);

        let (ct, ess) = rsp_data.scheme.encapsulate_with_rng(&pk, &mut rng).unwrap();
        assert_eq!(ct, rsp_data.ct);
        assert_eq!(ess, rsp_data.ss);

        let (dss, _) = rsp_data.scheme.decapsulate(&sk, &ct).unwrap();
        assert_eq!(dss, rsp_data.ss);
    }

    assert_eq!(count, 100, "official KAT file must contain all 100 cases");
}

/// Run all tests serially
#[ignore]
#[test]
fn test_vectors() {
    use std::fs::read_dir;

    let kat_dir = read_dir("./tests/efrodoKAT").unwrap();
    let mut rng = AesCtrDrbg::default();

    for path in kat_dir {
        let path = path.unwrap();
        if path.path().extension().unwrap() != "rsp" {
            continue;
        }
        let rsp_reader = RspReader::new(path.path());

        for rsp_data in rsp_reader {
            println!("{} Test {}", rsp_data.scheme, rsp_data.count + 1);
            rng.reseed(&rsp_data.seed);
            let (pk, sk) = rsp_data.scheme.generate_keypair(&mut rng);
            assert_eq!(pk, rsp_data.pk);
            assert_eq!(sk, rsp_data.sk);

            let (ct, ess) = rsp_data.scheme.encapsulate_with_rng(&pk, &mut rng).unwrap();
            assert_eq!(ct, rsp_data.ct);
            assert_eq!(ess, rsp_data.ss);

            let (dss, _) = rsp_data.scheme.decapsulate(&sk, &ct).unwrap();
            assert_eq!(dss, rsp_data.ss);
        }
    }
}

/// Decapsulation must not return `PKE.Decrypt` of a ciphertext that fails the
/// re-encryption check, or it becomes a decryption oracle that recovers the
/// secret key (same issue as RustCrypto's GHSA-hhq3-76c6-9rcj).
#[rstest]
#[case::aes640(frodo_kem_rs::Algorithm::FrodoKem640Aes)]
#[case::shake640(frodo_kem_rs::Algorithm::FrodoKem640Shake)]
#[case::aes976(frodo_kem_rs::Algorithm::FrodoKem976Aes)]
#[case::shake976(frodo_kem_rs::Algorithm::FrodoKem976Shake)]
#[case::aes1344(frodo_kem_rs::Algorithm::FrodoKem1344Aes)]
#[case::shake1344(frodo_kem_rs::Algorithm::FrodoKem1344Shake)]
#[case::ephemeral_aes640(frodo_kem_rs::Algorithm::EphemeralFrodoKem640Aes)]
#[case::ephemeral_shake640(frodo_kem_rs::Algorithm::EphemeralFrodoKem640Shake)]
#[case::ephemeral_aes976(frodo_kem_rs::Algorithm::EphemeralFrodoKem976Aes)]
#[case::ephemeral_shake976(frodo_kem_rs::Algorithm::EphemeralFrodoKem976Shake)]
#[case::ephemeral_aes1344(frodo_kem_rs::Algorithm::EphemeralFrodoKem1344Aes)]
#[case::ephemeral_shake1344(frodo_kem_rs::Algorithm::EphemeralFrodoKem1344Shake)]
fn decapsulate_does_not_return_decryption_of_rejected_ciphertext(
    #[case] alg: frodo_kem_rs::Algorithm,
) {
    let params = alg.params();
    let (ek, dk) = alg
        .generate_keypair_from_seed(vec![7u8; params.key_seed_length])
        .unwrap();
    let msg = vec![0xA5u8; params.message_length];
    let salt = vec![0x11u8; params.salt_length];
    let (ct, ss) = alg.encapsulate(&ek, &msg, &salt).unwrap();

    let (dec_ss, dec_msg) = alg.decapsulate(&dk, &ct).unwrap();
    assert_eq!(dec_ss, ss);
    assert_eq!(dec_msg, msg);

    // Flip the low bit of the last entry of C. The ciphertext still decrypts
    // to `msg`, but it is no longer a valid encapsulation, so it is rejected.
    let mut bytes = ct.value().to_vec();
    bytes[params.ciphertext_length - params.salt_length - 1] ^= 1;
    let rejected = alg.ciphertext_from_bytes(&bytes).unwrap();

    let (rej_ss, rej_msg) = alg.decapsulate(&dk, &rejected).unwrap();
    assert_ne!(rej_ss, ss);
    assert_eq!(rej_msg.len(), params.message_length);
    assert_ne!(
        rej_msg, msg,
        "decapsulate() returned the decryption of a rejected ciphertext"
    );
    assert_eq!(alg.decapsulate(&dk, &rejected).unwrap().1, rej_msg);
}
