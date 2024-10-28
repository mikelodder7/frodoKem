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

#[cfg(not(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes",
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake"
)))]
compile_error!("no algorithm feature enabled");

mod error;

pub use error::*;
use rand_core::CryptoRngCore;
use std::fmt::Debug;
use std::marker::PhantomData;

#[cfg(feature = "hazmat")]
pub mod hazmat;
#[cfg(not(feature = "hazmat"))]
mod hazmat;

use zeroize::{Zeroize, ZeroizeOnDrop};

use hazmat::{
    CiphertextRef, Frodo1344, Frodo640, Frodo976, FrodoKem1344Aes, FrodoKem1344Shake,
    FrodoKem640Aes, FrodoKem640Shake, FrodoKem976Aes, FrodoKem976Shake, Kem, Params, PublicKeyRef,
    SecretKeyRef,
};

/// A FrodoKEM ciphertext key
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Ciphertext(pub(crate) Vec<u8>);

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A FrodoKEM public key
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct PublicKey(pub(crate) Vec<u8>);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A FrodoKEM secret key
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct SecretKey(pub(crate) Vec<u8>);

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

/// A FrodoKEM shared secret
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct SharedSecret(pub(crate) Vec<u8>);

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

/// The supported FrodoKem algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Algorithm {
    #[cfg(feature = "frodo640aes")]
    /// The FrodoKEM-640-AES algorithm
    FrodoKem640Aes,
    #[cfg(feature = "frodo976aes")]
    /// The FrodoKEM-976-AES algorithm
    FrodoKem976Aes,
    #[cfg(feature = "frodo1344aes")]
    /// The FrodoKEM-1344-AES algorithm
    FrodoKem1344Aes,
    #[cfg(feature = "frodo640shake")]
    /// The FrodoKEM-640-SHAKE algorithm
    FrodoKem640Shake,
    #[cfg(feature = "frodo976shake")]
    /// The FrodoKEM-976-SHAKE algorithm
    FrodoKem976Shake,
    #[cfg(feature = "frodo1344shake")]
    /// The FrodoKEM-1344-SHAKE algorithm
    FrodoKem1344Shake,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        static ALGORITHMS: std::sync::LazyLock<std::collections::HashMap<Algorithm, String>> =
            std::sync::LazyLock::new(|| {
                let mut set = std::collections::HashMap::new();
                #[cfg(feature = "frodo640aes")]
                set.insert(
                    Algorithm::FrodoKem640Aes,
                    FrodoKem640Aes::default().algorithm(),
                );
                #[cfg(feature = "frodo976aes")]
                set.insert(
                    Algorithm::FrodoKem976Aes,
                    FrodoKem976Aes::default().algorithm(),
                );
                #[cfg(feature = "frodo1344aes")]
                set.insert(
                    Algorithm::FrodoKem1344Aes,
                    FrodoKem1344Aes::default().algorithm(),
                );
                #[cfg(feature = "frodo640shake")]
                set.insert(
                    Algorithm::FrodoKem640Shake,
                    FrodoKem640Shake::default().algorithm(),
                );
                #[cfg(feature = "frodo976shake")]
                set.insert(
                    Algorithm::FrodoKem976Shake,
                    FrodoKem976Shake::default().algorithm(),
                );
                #[cfg(feature = "frodo1344shake")]
                set.insert(
                    Algorithm::FrodoKem1344Shake,
                    FrodoKem1344Shake::default().algorithm(),
                );

                set
            });
        let ss = &(*ALGORITHMS)[self];
        write!(f, "{}", ss)
    }
}

impl std::str::FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static ALGORITHMS: std::sync::LazyLock<std::collections::HashMap<String, Algorithm>> =
            std::sync::LazyLock::new(|| {
                let mut set = std::collections::HashMap::new();
                #[cfg(feature = "frodo640aes")]
                set.insert(
                    FrodoKem640Aes::default().algorithm(),
                    Algorithm::FrodoKem640Aes,
                );
                #[cfg(feature = "frodo976aes")]
                set.insert(
                    FrodoKem976Aes::default().algorithm(),
                    Algorithm::FrodoKem976Aes,
                );
                #[cfg(feature = "frodo1344aes")]
                set.insert(
                    FrodoKem1344Aes::default().algorithm(),
                    Algorithm::FrodoKem1344Aes,
                );
                #[cfg(feature = "frodo640shake")]
                set.insert(
                    FrodoKem640Shake::default().algorithm(),
                    Algorithm::FrodoKem640Shake,
                );
                #[cfg(feature = "frodo976shake")]
                set.insert(
                    FrodoKem976Shake::default().algorithm(),
                    Algorithm::FrodoKem976Shake,
                );
                #[cfg(feature = "frodo1344shake")]
                set.insert(
                    FrodoKem1344Shake::default().algorithm(),
                    Algorithm::FrodoKem1344Shake,
                );

                set
            });
        (*ALGORITHMS)
            .get(s)
            .ok_or(Error::UnsupportedAlgorithm)
            .copied()
    }
}

impl Algorithm {
    /// Get the claimed NIST level
    pub fn claimed_nist_level(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::CLAIMED_NIST_LEVEL,
        }
    }

    /// Get the length of the message
    pub fn message_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::BYTES_MU,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::BYTES_MU,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::BYTES_MU,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::BYTES_MU,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::BYTES_MU,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::BYTES_MU,
        }
    }

    /// Get the length of the public key
    pub fn public_key_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::PUBLIC_KEY_LENGTH,
        }
    }

    /// Get the length of the secret key
    pub fn secret_key_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::SECRET_KEY_LENGTH,
        }
    }

    /// Get the length of the shared secret
    pub fn shared_secret_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::SHARED_SECRET_LENGTH,
        }
    }

    /// Get the length of the ciphertext
    pub fn ciphertext_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::CIPHERTEXT_LENGTH,
        }
    }

    /// Get the [`PublicKey`] from a [`SecretKey`]
    pub fn public_key_from_secret_key(&self, secret_key: &SecretKey) -> PublicKey {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                let sk = SecretKeyRef::<FrodoKem640Aes>(secret_key.0.as_slice(), PhantomData);
                PublicKey(sk.public_key().to_vec())
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                let sk = SecretKeyRef::<FrodoKem976Aes>(secret_key.0.as_slice(), PhantomData);
                PublicKey(sk.public_key().to_vec())
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                let sk = SecretKeyRef::<FrodoKem1344Aes>(secret_key.0.as_slice(), PhantomData);
                PublicKey(sk.public_key().to_vec())
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                let sk = SecretKeyRef::<FrodoKem640Shake>(secret_key.0.as_slice(), PhantomData);
                PublicKey(sk.public_key().to_vec())
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                let sk = SecretKeyRef::<FrodoKem976Shake>(secret_key.0.as_slice(), PhantomData);
                PublicKey(sk.public_key().to_vec())
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                let sk = SecretKeyRef::<FrodoKem1344Shake>(secret_key.0.as_slice(), PhantomData);
                PublicKey(sk.public_key().to_vec())
            }
        }
    }

    /// Obtain a secret key from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn secret_key_from_bytes(&self, buf: &[u8]) -> FrodoResult<SecretKey> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                hazmat::SecretKey::<FrodoKem640Aes>::from_slice(buf).map(|s| SecretKey(s.0))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                hazmat::SecretKey::<FrodoKem976Aes>::from_slice(buf).map(|s| SecretKey(s.0))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                hazmat::SecretKey::<FrodoKem1344Aes>::from_slice(buf).map(|s| SecretKey(s.0))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                hazmat::SecretKey::<FrodoKem640Shake>::from_slice(buf).map(|s| SecretKey(s.0))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                hazmat::SecretKey::<FrodoKem976Shake>::from_slice(buf).map(|s| SecretKey(s.0))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                hazmat::SecretKey::<FrodoKem1344Shake>::from_slice(buf).map(|s| SecretKey(s.0))
            }
        }
    }

    /// Obtain a public key from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn public_key_from_bytes(&self, buf: &[u8]) -> FrodoResult<PublicKey> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                hazmat::PublicKey::<FrodoKem640Aes>::from_slice(buf).map(|s| PublicKey(s.0))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                hazmat::PublicKey::<FrodoKem976Aes>::from_slice(buf).map(|s| PublicKey(s.0))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                hazmat::PublicKey::<FrodoKem1344Aes>::from_slice(buf).map(|s| PublicKey(s.0))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                hazmat::PublicKey::<FrodoKem640Shake>::from_slice(buf).map(|s| PublicKey(s.0))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                hazmat::PublicKey::<FrodoKem976Shake>::from_slice(buf).map(|s| PublicKey(s.0))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                hazmat::PublicKey::<FrodoKem1344Shake>::from_slice(buf).map(|s| PublicKey(s.0))
            }
        }
    }

    /// Obtain a ciphertext from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn ciphertext_from_bytes(&self, buf: &[u8]) -> FrodoResult<Ciphertext> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                hazmat::Ciphertext::<FrodoKem640Aes>::from_slice(buf).map(|s| Ciphertext(s.0))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                hazmat::Ciphertext::<FrodoKem976Aes>::from_slice(buf).map(|s| Ciphertext(s.0))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                hazmat::Ciphertext::<FrodoKem1344Aes>::from_slice(buf).map(|s| Ciphertext(s.0))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                hazmat::Ciphertext::<FrodoKem640Shake>::from_slice(buf).map(|s| Ciphertext(s.0))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                hazmat::Ciphertext::<FrodoKem976Shake>::from_slice(buf).map(|s| Ciphertext(s.0))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                hazmat::Ciphertext::<FrodoKem1344Shake>::from_slice(buf).map(|s| Ciphertext(s.0))
            }
        }
    }

    /// Obtain a shared secret from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn shared_secret_from_bytes(&self, buf: &[u8]) -> FrodoResult<SharedSecret> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                hazmat::SharedSecret::<FrodoKem640Aes>::from_slice(buf).map(|s| SharedSecret(s.0))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                hazmat::SharedSecret::<FrodoKem976Aes>::from_slice(buf).map(|s| SharedSecret(s.0))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                hazmat::SharedSecret::<FrodoKem1344Aes>::from_slice(buf).map(|s| SharedSecret(s.0))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                hazmat::SharedSecret::<FrodoKem640Shake>::from_slice(buf).map(|s| SharedSecret(s.0))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                hazmat::SharedSecret::<FrodoKem976Shake>::from_slice(buf).map(|s| SharedSecret(s.0))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => hazmat::SharedSecret::<FrodoKem1344Shake>::from_slice(buf)
                .map(|s| SharedSecret(s.0)),
        }
    }

    /// Generate a new keypair consisting of a [`PublicKey`] and a [`SecretKey`]
    pub fn generate_keypair(&self, rng: impl CryptoRngCore) -> (PublicKey, SecretKey) {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                let (pk, sk) = FrodoKem640Aes::default().generate_keypair(rng);
                (PublicKey(pk.0), SecretKey(sk.0))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                let (pk, sk) = FrodoKem976Aes::default().generate_keypair(rng);
                (PublicKey(pk.0), SecretKey(sk.0))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                let (pk, sk) = FrodoKem1344Aes::default().generate_keypair(rng);
                (PublicKey(pk.0), SecretKey(sk.0))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                let (pk, sk) = FrodoKem640Shake::default().generate_keypair(rng);
                (PublicKey(pk.0), SecretKey(sk.0))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                let (pk, sk) = FrodoKem976Shake::default().generate_keypair(rng);
                (PublicKey(pk.0), SecretKey(sk.0))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                let (pk, sk) = FrodoKem1344Shake::default().generate_keypair(rng);
                (PublicKey(pk.0), SecretKey(sk.0))
            }
        }
    }

    /// Encapsulate with given message to generate a [`SharedSecret`] and a [`Ciphertext`]
    pub fn encapsulate(
        &self,
        public_key: &PublicKey,
        msg: &[u8],
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                if <Frodo640 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (ct, ss) = FrodoKem640Aes::default().encapsulate(pk, msg);
                Ok((Ciphertext(ct.0), SharedSecret(ss.0)))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                if <Frodo976 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem976Aes::default().encapsulate(pk, msg);
                Ok((Ciphertext(pk.0), SharedSecret(sk.0)))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                if <Frodo1344 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem1344Aes::default().encapsulate(pk, msg);
                Ok((Ciphertext(pk.0), SharedSecret(sk.0)))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                if <Frodo640 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem640Shake::default().encapsulate(pk, msg);
                Ok((Ciphertext(pk.0), SharedSecret(sk.0)))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                if <Frodo976 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem976Shake::default().encapsulate(pk, msg);
                Ok((Ciphertext(pk.0), SharedSecret(sk.0)))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                if <Frodo1344 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem1344Shake::default().encapsulate(pk, msg);
                Ok((Ciphertext(pk.0), SharedSecret(sk.0)))
            }
        }
    }

    /// Encapsulate a message generated randomly to generate a [`SharedSecret`] and a [`Ciphertext`]
    pub fn encapsulate_with_rng(
        &self,
        public_key: &PublicKey,
        rng: impl CryptoRngCore,
    ) -> (Ciphertext, SharedSecret) {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (ct, ss) = FrodoKem640Aes::default().encapsulate_with_rng(pk, rng);
                (Ciphertext(ct.0), SharedSecret(ss.0))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem976Aes::default().encapsulate_with_rng(pk, rng);
                (Ciphertext(pk.0), SharedSecret(sk.0))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem1344Aes::default().encapsulate_with_rng(pk, rng);
                (Ciphertext(pk.0), SharedSecret(sk.0))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem640Shake::default().encapsulate_with_rng(pk, rng);
                (Ciphertext(pk.0), SharedSecret(sk.0))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem976Shake::default().encapsulate_with_rng(pk, rng);
                (Ciphertext(pk.0), SharedSecret(sk.0))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                let pk = PublicKeyRef(public_key.0.as_slice(), PhantomData);
                let (pk, sk) = FrodoKem1344Shake::default().encapsulate_with_rng(pk, rng);
                (Ciphertext(pk.0), SharedSecret(sk.0))
            }
        }
    }

    /// Decapsulate a [`Ciphertext`] to generate a [`SharedSecret`]
    pub fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> (SharedSecret, Vec<u8>) {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                let sk = SecretKeyRef(secret_key.0.as_slice(), PhantomData);
                let ct = CiphertextRef(ciphertext.0.as_slice(), PhantomData);
                let (ss, mu) = FrodoKem640Aes::default().decapsulate(sk, ct);
                (SharedSecret(ss.0), mu)
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                let sk = SecretKeyRef(secret_key.0.as_slice(), PhantomData);
                let ct = CiphertextRef(ciphertext.0.as_slice(), PhantomData);
                let (ss, mu) = FrodoKem976Aes::default().decapsulate(sk, ct);
                (SharedSecret(ss.0), mu)
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                let sk = SecretKeyRef(secret_key.0.as_slice(), PhantomData);
                let ct = CiphertextRef(ciphertext.0.as_slice(), PhantomData);
                let (ss, mu) = FrodoKem1344Aes::default().decapsulate(sk, ct);
                (SharedSecret(ss.0), mu)
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                let sk = SecretKeyRef(secret_key.0.as_slice(), PhantomData);
                let ct = CiphertextRef(ciphertext.0.as_slice(), PhantomData);
                let (ss, mu) = FrodoKem640Shake::default().decapsulate(sk, ct);
                (SharedSecret(ss.0), mu)
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                let sk = SecretKeyRef(secret_key.0.as_slice(), PhantomData);
                let ct = CiphertextRef(ciphertext.0.as_slice(), PhantomData);
                let (ss, mu) = FrodoKem976Shake::default().decapsulate(sk, ct);
                (SharedSecret(ss.0), mu)
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                let sk = SecretKeyRef(secret_key.0.as_slice(), PhantomData);
                let ct = CiphertextRef(ciphertext.0.as_slice(), PhantomData);
                let (ss, mu) = FrodoKem1344Shake::default().decapsulate(sk, ct);
                (SharedSecret(ss.0), mu)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{RngCore, SeedableRng};
    use rstest::*;
    use safe_oqs::kem;

    #[rstest]
    #[case::aes640(Algorithm::FrodoKem640Aes, kem::Algorithm::FrodoKem640Aes)]
    fn works(#[case] alg: Algorithm, #[case] safe_alg: kem::Algorithm) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        for _ in 0..10 {
            let (our_pk, our_sk) = alg.generate_keypair(&mut rng);
            let kem = kem::Kem::new(safe_alg).unwrap();

            let opt_pk = kem.public_key_from_bytes(&our_pk.0);
            assert!(opt_pk.is_some());
            let opt_sk = kem.secret_key_from_bytes(&our_sk.0);
            assert!(opt_sk.is_some());

            let their_pk = opt_pk.unwrap();
            let their_sk = opt_sk.unwrap();

            let mut mu = vec![0u8; alg.message_length()];
            rng.fill_bytes(&mut mu);
            let (our_ct, our_ess) = alg.encapsulate(&our_pk, &mu).unwrap();
            let (our_dss, mu_prime) = alg.decapsulate(&our_sk, &our_ct);
            assert_eq!(our_ess.0, our_dss.0);
            assert_eq!(mu, mu_prime);

            let their_ct = kem.ciphertext_from_bytes(&our_ct.0).unwrap();
            let their_ss = kem.decapsulate(&their_sk, &their_ct).unwrap();
        }
    }
}
