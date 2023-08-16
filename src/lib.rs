#![allow(dead_code)]

mod client;
pub mod credentials;
pub mod error;

pub type Result<T> = std::result::Result<T, error::Error>;
