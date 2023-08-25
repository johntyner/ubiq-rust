//! Interfaces for encrypting data
//!
//! # Examples
//! ## Simple
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
//! ## Piecewise
//! ```rust
//! use ubiq::credentials::Credentials;
//! use ubiq::encryption::Encryption;
//! use ubiq::decryption::decrypt;
//!
//! let creds = Credentials::new(None, None).unwrap();
//! let pt = b"abcdefghijklmnopqrstuvwxyz";
//!
//! // note that we pass `1` to the new() function, indicating
//! // that the encryption key will be used once
//! let mut enc = Encryption::new(&creds, 1).unwrap();
//!
//! /*
//!  * pt can be passed to the encryption process in
//!  * as many or as few pieces as desired
//!  */
//!
//! let mut ct = enc.begin().unwrap();
//! ct.extend(enc.update(&pt[0..4]).unwrap());
//! ct.extend(enc.update(&pt[4..11]).unwrap());
//! ct.extend(enc.update(&pt[11..]).unwrap());
//! ct.extend(enc.end().unwrap());
//!
//! let rec = decrypt(&creds, &ct).unwrap();
//!
//! assert!(pt != &ct[..]);
//! assert!(pt == &rec[..]);
//!
//! /*
//!  * if the encryption object was created for more than
//!  * a single use (by passing a number larger than 1 to
//!  * the new() function), then the enc object could now
//!  * be reused by following the begin(), update()...,
//!  * end() process shown above for as many times as
//!  * specified by the call to new()
//!  */
//! ```

use crate::algorithm;
use crate::cipher;
use crate::client::Client;
use crate::credentials::Credentials;
use crate::error::Error;
use crate::header::Header;
use crate::result::Result;
use crate::session;

use rand::RngCore;

const ENCRYPTION_KEY_PATH: &str = "api/v0/encryption/key";

#[derive(serde::Deserialize)]
struct NewEncryptionResponseSecurityModel {
    algorithm: String,
    // enable_data_fragmentation: bool,
}

#[derive(serde::Deserialize)]
struct NewEncryptionResponse {
    encrypted_private_key: String,
    encryption_session: String,
    key_fingerprint: String,
    wrapped_data_key: String,
    encrypted_data_key: String,
    max_uses: usize,
    security_model: NewEncryptionResponseSecurityModel,
}

#[derive(Debug)]
/// Structure encompassing parameters used for encrypting data
///
/// Using this structure, a caller is able to encrypt a plaintext
/// by feeding it to the member functions in a piecewise fashion
/// (or by doing so all at once). The encryption object can be reused
/// to encrypt as many plaintexts as were initially specified by the
/// call to `new()`
pub struct Encryption<'a> {
    session: session::Session<'a>,
}

impl Encryption<'_> {
    fn s_close(
        client: &Client,
        host: &String,
        id: &Option<String>,
        fp: &String,
        uses: &session::SessionKeyUses,
    ) -> Result<()> {
        if uses.cur < uses.max {
            let rsp = client.patch(
                &format!(
                    "{}/{}/{}/{}",
                    host,
                    ENCRYPTION_KEY_PATH,
                    fp,
                    id.as_ref().unwrap(),
                ),
                "application/json".to_string(),
                format!(
                    "{{\
                       \"requested\": {},\
                       \"actual\": {}\
                     }}",
                    uses.max, uses.cur,
                ),
            )?;

            if !rsp.status().is_success() {
                return Err(Error::new(&format!(
                    "failed to update encryption key: {}",
                    rsp.status().as_str()
                )));
            }
        }

        Ok(())
    }

    pub fn new<'a>(creds: &Credentials, uses: usize) -> Result<Encryption<'a>> {
        let client = std::rc::Rc::new(Client::new(creds));
        let host = std::rc::Rc::new(creds.host().clone());

        let rsp = client.post(
            &format!("{}/{}", host, ENCRYPTION_KEY_PATH),
            "application/json".to_string(),
            format!(
                "{{\
                   \"uses\": {}\
                 }}",
                uses
            ),
        )?;

        match rsp.json::<NewEncryptionResponse>() {
            Err(e) => return Err(Error::new(&e.to_string())),
            Ok(msg) => Ok(Encryption {
                session: session::Session::new(
                    std::rc::Rc::clone(&client),
                    std::rc::Rc::clone(&host),
                    Some(msg.encryption_session),
                    &msg.key_fingerprint,
                    algorithm::get_by_name(&msg.security_model.algorithm)?,
                    &msg.encrypted_private_key,
                    &msg.wrapped_data_key,
                    &msg.encrypted_data_key,
                    msg.max_uses,
                    creds.srsa(),
                    Self::s_close,
                )?,
            }),
        }
    }

    /// Begin a new encryption "session"
    ///
    /// Encryption of a plaintext consists of a `begin()`, some number
    /// of `update()` calls, and an `end()`. It is an error to call
    /// `begin()` more than once without an intervening `end()`.
    pub fn begin(&mut self) -> Result<Vec<u8>> {
        if self.session.ctx.is_some() {
            return Err(Error::new("encryption already in progress"));
        } else if self.session.key.uses.cur >= self.session.key.uses.max {
            return Err(Error::new("encryption key has expired"));
        }

        let mut iv = Vec::<u8>::new();
        iv.resize(self.session.algo.len.iv, 0);
        rand::thread_rng().fill_bytes(&mut iv);

        let hdr = Header::new(
            if self.session.algo.len.tag > 0 {
                crate::header::V0_FLAG_AAD
            } else {
                0
            },
            self.session.algo.id,
            &iv,
            &self.session.key.enc,
        );
        let ct = hdr.serialize();

        self.session.ctx = Some(cipher::CipherCtx::new(
            cipher::CipherOp::Encrypt,
            self.session.algo.name,
            &self.session.key.raw,
            &iv,
            if (hdr.flags & crate::header::V0_FLAG_AAD) != 0 {
                Some(&ct)
            } else {
                None
            },
        )?);

        self.session.key.uses.cur += 1;

        Ok(ct)
    }

    /// Input (some) plaintext for encryption
    ///
    /// The update function writes data into the Encryption object.
    /// Ciphertext data may or may not be returned with each call to
    /// this function.
    pub fn update(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        if self.session.ctx.is_none() {
            return Err(Error::new("encryption not yet started"));
        }

        self.session.ctx.as_mut().unwrap().update(pt)
    }

    /// End an encryption "session"
    ///
    /// After all plaintext has been written to the object via the
    /// `update()` function, the caller must call this function to finalize
    /// the encryption. Any remaining plaintext will be returned along
    /// with any authentication information produced by the algorithm.
    pub fn end(&mut self) -> Result<Vec<u8>> {
        if self.session.ctx.is_none() {
            return Err(Error::new("encryption not yet started"));
        }

        let res = self.session.ctx.as_mut().unwrap().finalize(None);
        self.session.ctx = None;

        return res;
    }

    /// Encrypt a single plaintext in one shot
    ///
    /// This function is equivalent to calling `begin()`, `update(pt)`,
    /// and `end()`
    pub fn cipher(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let mut ct = self.begin()?;
        ct.extend(self.update(pt)?);
        ct.extend(self.end()?);
        Ok(ct)
    }
}

/// Encrypt a single plaintext with a unique key
///
/// This function is equivalent to creating a new Encryption object
/// for a single use and calling `begin()`, `update(pt)`, and `end()`.
pub fn encrypt(c: &Credentials, pt: &[u8]) -> Result<Vec<u8>> {
    Encryption::new(&c, 1)?.cipher(&pt)
}

#[cfg(test)]
mod tests {}
