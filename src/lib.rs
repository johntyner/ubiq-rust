//! Client library for the Ubiq platform
//!
//! Provides simple interfaces for achieving data encryption
//! using the Ubiq platform

pub(crate) mod algorithm;
pub(crate) mod client;
pub mod credentials;
pub mod decryption;
pub mod encryption;
pub(crate) mod header;
pub(crate) mod support;

/// Common result interface used by the library
pub mod result {
    pub type Result<T> = std::result::Result<T, crate::error::Error>;
}

/// Errors returned by the Ubiq library
pub mod error {
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
}
