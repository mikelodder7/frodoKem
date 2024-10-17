/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A FrodoKEM ciphertext
#[derive(Clone, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Ciphertext(pub(crate) Vec<u8>);

/// A FrodoKEM public key
#[derive(Clone, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct PublicKey(pub(crate) Vec<u8>);

/// A FrodoKEM secret key
#[derive(Clone, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct SecretKey(pub(crate) Vec<u8>);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

/// A FrodoKEM shared secret
#[derive(Clone, Debug, Deserialize, Serialize)]
#[repr(transparent)]
pub struct SharedSecret(pub(crate) Vec<u8>);

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}
