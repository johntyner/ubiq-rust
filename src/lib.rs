#![allow(dead_code)]

pub(crate) mod algorithm;
pub mod base64;
pub(crate) mod client;
pub mod credentials;
pub mod encryption;
pub mod error;
pub(crate) mod header;
pub(crate) mod support;

pub type Result<T> = std::result::Result<T, error::Error>;
