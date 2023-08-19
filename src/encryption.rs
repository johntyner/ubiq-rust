use crate::algorithm;
use crate::algorithm::Algorithm;
use crate::client::Client;
use crate::credentials::Credentials;
use crate::error::Error;
use crate::header::Header;
use crate::result::Result;
use crate::support;

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
struct EncryptionSessionKeyUses {
    max: usize,
    cur: usize,
}

#[derive(Debug)]
struct EncryptionSessionKey {
    raw: Vec<u8>,
    enc: Vec<u8>,

    fingerprint: String,

    uses: EncryptionSessionKeyUses,
}

#[derive(Debug)]
struct EncryptionSession<'a> {
    client: Client,
    host: String,

    id: String,

    key: EncryptionSessionKey,

    algo: &'a Algorithm<'a>,
    ctx: Option<support::cipher::CipherCtx<'a>>,
}

impl EncryptionSession<'_> {
    pub fn new<'a>(
        creds: &Credentials,
        uses: usize,
    ) -> Result<EncryptionSession<'a>> {
        let client = Client::new(&creds);
        let host = creds.host().clone();

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

        let msg: NewEncryptionResponse;
        match rsp.json::<NewEncryptionResponse>() {
            Err(e) => return Err(Error::from_string(e.to_string())),
            Ok(ne) => msg = ne,
        }

        Ok(EncryptionSession {
            client: client,
            host: host,

            id: msg.encryption_session,

            key: EncryptionSessionKey {
                raw: support::unwrap_data_key(
                    &support::base64::decode(&msg.wrapped_data_key)?,
                    &msg.encrypted_private_key,
                    creds.srsa(),
                )?,
                enc: support::base64::decode(&msg.encrypted_data_key)?,

                fingerprint: msg.key_fingerprint,

                uses: EncryptionSessionKeyUses {
                    max: msg.max_uses,
                    cur: 0,
                },
            },

            algo: algorithm::get_by_name(&msg.security_model.algorithm)?,
            ctx: None,
        })
    }

    pub fn close(&mut self) -> Result<()> {
        let cur = self.key.uses.cur;
        let max = self.key.uses.max;

        self.key.uses.cur = 0;
        self.key.uses.max = 0;

        if cur < max {
            let rsp = self.client.patch(
                &format!(
                    "{}/{}/{}/{}",
                    self.host,
                    ENCRYPTION_KEY_PATH,
                    self.key.fingerprint,
                    self.id
                ),
                "application/json".to_string(),
                format!(
                    "{{\
                       \"requested\": {},\
                       \"actual\": {}\
                     }}",
                    max, cur,
                ),
            )?;

            if !rsp.status().is_success() {
                return Err(Error::from_string(format!(
                    "failed to update encryption key: {}",
                    rsp.status().as_str()
                )));
            }
        }

        Ok(())
    }
}

impl Drop for EncryptionSession<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Debug)]
pub struct Encryption<'a> {
    session: EncryptionSession<'a>,
}

impl Encryption<'_> {
    pub fn new<'a>(creds: &Credentials, uses: usize) -> Result<Encryption<'a>> {
        Ok(Encryption {
            session: EncryptionSession::new(creds, uses)?,
        })
    }

    pub fn begin(&mut self) -> Result<Vec<u8>> {
        if self.session.ctx.is_some() {
            return Err(Error::from_str("encryption already in progress"));
        } else if self.session.key.uses.cur >= self.session.key.uses.max {
            return Err(Error::from_str("encryption key has expired"));
        }

        let mut iv = Vec::<u8>::new();
        iv.resize(self.session.algo.len.iv, 0);
        support::getrandom(&mut iv[..])?;

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

        self.session.ctx = Some(support::encryption::init(
            self.session.algo,
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

    pub fn update(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        if self.session.ctx.is_none() {
            return Err(Error::from_str("encryption not yet started"));
        }

        support::encryption::update(self.session.ctx.as_mut().unwrap(), pt)
    }

    pub fn end(&mut self) -> Result<Vec<u8>> {
        if self.session.ctx.is_none() {
            return Err(Error::from_str("encryption not yet started"));
        }

        let res =
            support::encryption::finalize(self.session.ctx.as_mut().unwrap());
        self.session.ctx = None;

        return res;
    }

    pub fn close(&mut self) -> Result<()> {
        self.session.close()
    }

    pub fn cipher(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let mut ct = self.begin()?;
        ct.extend(self.update(pt)?);
        ct.extend(self.end()?);
        Ok(ct)
    }
}

impl Drop for Encryption<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub fn encrypt(c: &Credentials, pt: &[u8]) -> Result<Vec<u8>> {
    Encryption::new(&c, 1)?.cipher(&pt)
}

#[cfg(test)]
mod tests {}
