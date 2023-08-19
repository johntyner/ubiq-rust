#![allow(dead_code)]

pub(crate) mod algorithm;
pub(crate) mod client;
pub mod credentials;
pub mod decryption;
pub mod encryption;
pub(crate) mod header;
pub(crate) mod support;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    why: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(f, "{}", self.why);
    }
}

impl Error {
    pub fn from_string(why: String) -> Error {
        return Error { why: why };
    }

    pub fn from_str(why: &str) -> Error {
        return Error {
            why: why.to_string(),
        };
    }
}
