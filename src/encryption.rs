use super::algorithm;
use super::algorithm::Algorithm;
use super::client::Client;
use super::credentials::Credentials;
use super::header::Header;
use super::support;
use super::Error;
use super::Result;

#[derive(serde::Deserialize)]
struct NewEncryptionResponseSecurityModel {
    algorithm: String,
    enable_data_fragmentation: bool,
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
struct EncryptionKeyUses {
    max: usize,
    cur: usize,
}

#[derive(Debug)]
struct EncryptionKey {
    raw: Vec<u8>,
    enc: Vec<u8>,
    fingerprint: String,
    uses: EncryptionKeyUses,
}

#[derive(Debug)]
struct Encryption<'a> {
    client: Client,
    host: String,

    session: String,

    key: EncryptionKey,

    algo: &'a Algorithm<'a>,
    ctx: Option<support::cipher::CipherCtx<'a>>,
}

const ENCRYPTION_KEY_PATH: &str = "api/v0/encryption/key";

impl Encryption<'_> {
    pub fn new<'a>(creds: &Credentials, uses: u32) -> Result<Encryption<'a>> {
        let client = Client::new(creds);
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

        Ok(Encryption {
            client: client,
            host: host,

            session: msg.encryption_session,

            key: EncryptionKey {
                enc: support::base64::decode(&msg.encrypted_data_key)?,
                raw: support::unwrap_data_key(
                    &msg.wrapped_data_key,
                    &msg.encrypted_private_key,
                    creds.srsa(),
                )?,

                fingerprint: msg.key_fingerprint,

                uses: EncryptionKeyUses {
                    max: msg.max_uses,
                    cur: 0,
                },
            },

            algo: algorithm::get_by_name(&msg.security_model.algorithm)?,
            ctx: None,
        })
    }

    pub fn begin(&mut self) -> Result<Vec<u8>> {
        if self.ctx.is_some() {
            return Err(Error::from_str("encryption already in progress"));
        } else if self.key.uses.cur >= self.key.uses.max {
            return Err(Error::from_str("encryption key has expired"));
        }

        let mut iv = Vec::<u8>::new();
        iv.resize(self.algo.len.iv, 0);
        support::getrandom(&mut iv[..])?;

        let hdr = Header::new(0, self.algo.id, &iv, &self.key.enc);
        let vhdr = hdr.serialize();

        self.ctx = Some(support::encryption::init(
            &self.algo,
            &self.key.raw,
            &iv,
            Some(&vhdr),
        )?);

        self.key.uses.cur += 1;

        Ok(vhdr)
    }

    pub fn update(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        if self.ctx.is_none() {
            return Err(Error::from_str("encryption not yet started"));
        }

        support::encryption::update(self.ctx.as_mut().unwrap(), pt)
    }

    pub fn end(&mut self) -> Result<Vec<u8>> {
        if self.ctx.is_none() {
            return Err(Error::from_str("encryption not yet started"));
        }

        let res = support::encryption::finalize(self.ctx.as_mut().unwrap());
        self.ctx = None;

        return res;
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
                    self.session
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

impl Drop for Encryption<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub fn encrypt(c: &Credentials, pt: &[u8]) -> Result<Vec<u8>> {
    let mut enc = Encryption::new(&c, 1)?;
    let mut ct: Vec<u8>;

    ct = enc.begin()?;
    ct.extend(enc.update(pt)?);
    ct.extend(enc.end()?);

    Ok(ct)
}

#[cfg(test)]
mod tests {
    use super::Encryption;
    use crate::credentials::Credentials;

    fn new_encryption<'a>(uses: u32) -> Encryption<'a> {
        let res = Credentials::new(None, None);
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());

        let res = Encryption::new(&res.unwrap(), uses);
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());

        res.unwrap()
    }

    #[test]
    fn no_encryption() {
        let mut enc = new_encryption(1);
        let res = enc.close();
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
    }

    #[test]
    fn simple_encryption() {
        let res = Credentials::new(None, None);
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());

        let res = super::encrypt(&res.unwrap(), &vec![1, 2, 3][..]);
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
    }
}
