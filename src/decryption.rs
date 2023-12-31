//! Interfaces for decrypting data
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
//! use ubiq::encryption::encrypt;
//! use ubiq::decryption::Decryption;
//!
//! let creds = Credentials::new(None, None).unwrap();
//! let ct = encrypt(&creds, b"abc").unwrap();
//!
//! let mut dec = Decryption::new(&creds).unwrap();
//!
//! /*
//!  * ct can be passed to the decryption process in
//!  * as many or as few pieces as desired
//!  */
//!
//! let mut pt = dec.begin().unwrap();
//! pt.extend(dec.update(&ct[0..3]).unwrap());
//! pt.extend(dec.update(&ct[3..9]).unwrap());
//! pt.extend(dec.update(&ct[9..24]).unwrap());
//! pt.extend(dec.update(&ct[24..]).unwrap());
//! pt.extend(dec.end().unwrap());
//!
//! assert!(pt != ct);
//! assert!(pt == b"abc");
//!
//! /*
//!  * the dec object can now be reused by following the
//!  * begin(), update()..., end() process shown above for
//!  * as many times as desired.
//!  */
//! ```

use crate::algorithm;
use crate::base64;
use crate::cipher;
use crate::client::Client;
use crate::credentials::Credentials;
use crate::error::Error;
use crate::header::Header;
use crate::result::Result;
use crate::session;

const DECRYPTION_KEY_PATH: &str = "api/v0/decryption/key";

#[derive(serde::Deserialize)]
struct NewDecryptionResponse {
    encrypted_private_key: String,
    // this should just be a String, but the server is currently
    // returning `null` in this variable.
    // see also: DecryptionSession::close()
    encryption_session: Option<String>,
    key_fingerprint: String,
    wrapped_data_key: String,
}

/// Structure encompassing parameters used for decrypting data
///
/// Using this structure, a caller is able to decrypt a ciphertext
/// by feeding it to the member functions in a piecewise fashion
/// (or by doing so all at once). In addition, if multiple, unique
/// ciphertexts were encrypted with the same key, this object can
/// be used to decrypt them without having to communicate with the
/// server multiple times.
pub struct Decryption<'a> {
    client: std::rc::Rc<Client>,
    host: std::rc::Rc<String>,

    srsa: String,
    session: Option<session::Session<'a>>,

    buf: Vec<u8>,
}

impl Decryption<'_> {
    /// Create a new decryption object
    pub fn new<'a>(creds: &Credentials) -> Result<Decryption<'a>> {
        Ok(Decryption {
            client: std::rc::Rc::new(Client::new(creds)),
            host: std::rc::Rc::new(creds.host().clone()),

            srsa: creds.srsa().clone(),
            session: None,

            buf: Vec::new(),
        })
    }

    fn s_close(
        client: &Client,
        host: &String,
        id: &Option<String>,
        fp: &String,
        uses: &session::SessionKeyUses,
    ) -> Result<()> {
        if uses.cur > 0 && id.as_ref().is_some() {
            client.patch(
                &format!(
                    "{}/{}/{}/{}",
                    host,
                    DECRYPTION_KEY_PATH,
                    fp,
                    id.as_ref().unwrap(),
                ),
                "application/json".to_string(),
                format!(
                    "{{\
                       \"uses\": {}\
                     }}",
                    uses.cur,
                ),
            )?;
        }

        Ok(())
    }

    fn new_session<'a>(
        &self,
        algoid: usize,
        edk: &[u8],
    ) -> Result<session::Session<'a>> {
        let s_edk = base64::encode(edk);

        let rsp = self.client.post(
            &format!("{}/{}", self.host, DECRYPTION_KEY_PATH),
            "application/json".to_string(),
            format!(
                "{{\
                   \"encrypted_data_key\": \"{}\"\
                 }}",
                s_edk,
            ),
        )?;

        match rsp.json::<NewDecryptionResponse>() {
            Err(e) => Err(Error::new(&e.to_string())),
            Ok(msg) => Ok(session::Session::new(
                std::rc::Rc::clone(&self.client),
                std::rc::Rc::clone(&self.host),
                msg.encryption_session,
                &msg.key_fingerprint,
                algorithm::get_by_id(algoid)?,
                &msg.encrypted_private_key,
                &msg.wrapped_data_key,
                &s_edk,
                0,
                &self.srsa,
                Self::s_close,
            )?),
        }
    }

    /// Begin a new decryption "session"
    ///
    /// Decryption of a ciphertext consists of a `begin()`, some number
    /// of `update()` calls, and an `end()`. It is an error to call
    /// `begin()` more than once without an intervening `end()`.
    pub fn begin(&mut self) -> Result<Vec<u8>> {
        if self.session.is_some()
            && self.session.as_ref().unwrap().ctx.is_some()
        {
            return Err(Error::new("decryption already in progress"));
        }

        // because no ciphertext has been input yet, no plaintext
        // is returned, but this is done so that the Encryption and
        // Decryption interfaces are the same/similar
        Ok(Vec::<u8>::new())
    }

    /// Input (some) ciphertext for decryption
    ///
    /// The update function writes data into the Decryption object.
    /// Plaintext data may or may not be returned with each call to
    /// this function.
    pub fn update(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        self.buf.extend(ct);

        if self.session.is_none()
            || self.session.as_ref().unwrap().ctx.is_none()
        {
            let hlen = Header::can_deserialize(&self.buf)?;

            if hlen > 0 {
                let mut buf = std::mem::take(&mut self.buf);
                let hdr = Header::deserialize(&buf)?;

                if hdr.version != 0 {
                    return Err(Error::new("unsupported header version"));
                }

                if self.session.is_some()
                    && self.session.as_ref().unwrap().key.enc != hdr.key
                {
                    self.session = None;
                }

                if self.session.is_none() {
                    self.session =
                        Some(self.new_session(hdr.algorithm, &hdr.key)?);
                }

                let mut s = self.session.as_mut().unwrap();
                s.ctx = Some(cipher::CipherCtx::new(
                    cipher::CipherOp::Decrypt,
                    s.algo.name,
                    &s.key.raw,
                    hdr.iv,
                    if (hdr.flags & crate::header::V0_FLAG_AAD) != 0 {
                        Some(&buf[0..hlen])
                    } else {
                        None
                    },
                )?);

                s.key.uses.cur += 1;

                buf.drain(0..hlen);
                self.buf = buf;
            }
        }

        let mut pt = Vec::<u8>::new();

        if self.session.is_some()
            && self.session.as_ref().unwrap().ctx.is_some()
        {
            let s = self.session.as_mut().unwrap();

            if self.buf.len() > s.algo.len.tag {
                let sz = self.buf.len() - s.algo.len.tag;
                pt = s.ctx.as_mut().unwrap().update(&self.buf[0..sz])?;
                self.buf.drain(0..sz);
            }
        }

        Ok(pt)
    }

    /// End a decryption "session"
    ///
    /// After all ciphertext has been written to the object via the
    /// `update()` function, the caller must call this function to finalize
    /// the decryption. Any remaining plaintext will be returned. If the
    /// algorithm in use is authenticated, an error may be returned instead
    /// if the authentication process fails.
    ///
    /// Note that if the algorithm in use is authenticated, any error in
    /// the authentication process will not be reported until this function
    /// is called. Therefore, when using an authenticated algorithm, output
    /// should not be trusted until this function returns successfully.
    pub fn end(&mut self) -> Result<Vec<u8>> {
        let mut pt = Vec::<u8>::new();

        if self.session.is_some()
            && self.session.as_ref().unwrap().ctx.is_some()
        {
            let s = self.session.as_mut().unwrap();

            pt = s.ctx.as_mut().unwrap().finalize(if self.buf.len() > 0 {
                Some(&self.buf)
            } else {
                None
            })?;

            self.buf.truncate(0);
            s.ctx = None;
        }

        Ok(pt)
    }

    /// Decrypt a single ciphertext in one shot
    ///
    /// This function is equivalent to calling `begin()`, `update(ct)`,
    /// and `end()`
    pub fn cipher(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let mut pt = self.begin()?;
        pt.extend(self.update(ct)?);
        pt.extend(self.end()?);
        Ok(pt)
    }
}

/// Decrypt a single ciphertext
///
/// This function is equivalent to creating a new Decryption object
/// calling `begin()`, `update(pt)`, and `end()`.
pub fn decrypt(c: &Credentials, ct: &[u8]) -> Result<Vec<u8>> {
    Decryption::new(&c)?.cipher(&ct)
}

#[cfg(test)]
mod tests {
    #[test]
    fn reuse_session() -> crate::result::Result<()> {
        let pt = b"abc";

        let creds = crate::credentials::Credentials::new(None, None)?;
        let ct = crate::encryption::encrypt(&creds, &pt[..])?;
        let mut dec = crate::decryption::Decryption::new(&creds)?;

        let rec = dec.cipher(&ct)?;
        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
        let fp1 = dec.session.as_ref().unwrap().key.fingerprint.clone();
        let s1 =
            dec.session.as_ref().unwrap() as *const crate::session::Session<'_>;

        let rec = dec.cipher(&ct)?;
        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
        let fp2 = dec.session.as_ref().unwrap().key.fingerprint.clone();
        let s2 =
            dec.session.as_ref().unwrap() as *const crate::session::Session<'_>;

        /*
         * we really want to compare the session.id, but
         * the server is currently returning `null` in that
         * field which in unhelpful.
         */
        assert!(fp1 == fp2 && s1 == s2);

        Ok(())
    }

    #[test]
    fn change_session() -> crate::result::Result<()> {
        let pt = b"abc";

        let creds = crate::credentials::Credentials::new(None, None)?;
        let mut dec = crate::decryption::Decryption::new(&creds)?;

        let ct = crate::encryption::encrypt(&creds, &pt[..])?;
        let rec = dec.cipher(&ct)?;
        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
        let fp1 = dec.session.as_ref().unwrap().key.fingerprint.clone();

        let ct = crate::encryption::encrypt(&creds, &pt[..])?;
        let rec = dec.cipher(&ct)?;
        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
        let fp2 = dec.session.as_ref().unwrap().key.fingerprint.clone();

        /* different key fingerprints means different sessions */
        assert!(fp1 != fp2);

        Ok(())
    }
}
