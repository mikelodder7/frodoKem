/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use thiserror::Error;

/// The errors that can occur for FrodoKEM
#[derive(Error, Copy, Clone, Debug)]
pub enum Error {}

/// The result type for FrodoKEM
pub type FrodoResult<T> = Result<T, Error>;
