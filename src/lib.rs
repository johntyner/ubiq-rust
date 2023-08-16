#![allow(dead_code)]

pub mod base64;
pub(crate) mod client;
pub mod credentials;
pub mod encryption;
pub mod error;

pub type Result<T> = std::result::Result<T, error::Error>;
