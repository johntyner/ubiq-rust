//! Client library for the Ubiq platform
//!
//! Provides client interfaces for encrypting and decrypting data
//! using the [`Ubiq`] [`platform`].
//!
//! # Example
//! ```rust
//! use ubiq::credentials::Credentials;
//! use ubiq::encryption::encrypt;
//! use ubiq::decryption::decrypt;
//!
//! let creds = Credentials::new(None, None).unwrap();
//!
//! let ct = encrypt(&creds, b"abc").unwrap();
//! let pt = decrypt(&creds, &ct).unwrap();
//!
//! assert!(pt != ct);
//! assert!(pt == b"abc");
//! ```
//!
//! [`Ubiq`]: https://www.ubiqsecurity.com/
//! [`platform`]: https://dashboard.ubiqsecurity.com/login

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
    /// Structure used to convey errors to users of the library
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
        /// Construct an error from a string reference
        pub fn new(why: &str) -> Error {
            return Error {
                why: why.to_string(),
            };
        }
    }

    impl From<openssl::error::ErrorStack> for Error {
        fn from(e: openssl::error::ErrorStack) -> Self {
            Error::new(&e.to_string())
        }
    }
}
