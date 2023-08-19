use super::algorithm::Algorithm;
use super::client::Client;
use super::credentials::Credentials;
use super::header::Header;
use super::support;
use crate::Error;
use crate::Result;

#[derive(serde::Deserialize)]
struct NewDecryptionResponse {
    encrypted_private_key: String,
    encryption_session: Option<String>,
    key_fingerprint: String,
    wrapped_data_key: String,
}

#[derive(Debug)]
struct DecryptionSessionKey {
    raw: Vec<u8>,
    enc: Vec<u8>,

    fingerprint: String,

    uses: usize,
}

struct DecryptionSession<'a> {
    id: Option<String>,

    key: DecryptionSessionKey,

    algo: &'a Algorithm<'a>,
    ctx: Option<support::cipher::CipherCtx<'a>>,
}

pub struct Decryption<'a> {
    client: Client,
    host: String,

    srsa: String,
    session: Option<DecryptionSession<'a>>,

    buf: Vec<u8>,
}

const DECRYPTION_KEY_PATH: &str = "api/v0/decryption/key";

impl Decryption<'_> {
    pub fn new<'a>(creds: &Credentials) -> Result<Decryption<'a>> {
        Ok(Decryption {
            client: Client::new(creds),
            host: creds.host().clone(),

            srsa: creds.srsa().clone(),
            session: None,

            buf: Vec::new(),
        })
    }

    pub fn begin(&mut self) -> Result<Vec<u8>> {
        if self.session.is_some() {
            return Err(Error::from_str("decryption already in progress"));
        }

        Ok(Vec::<u8>::new())
    }

    pub fn update(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let mut pt = Vec::<u8>::new();
        let mut buf = std::mem::take(&mut self.buf);

        buf.extend(ct);

        if self.session.is_none()
            || self.session.as_ref().unwrap().ctx.is_none()
        {
            let hlen = Header::can_deserialize(&buf)?;

            if hlen > 0 {
                let hdr = Header::deserialize(&buf)?;

                if hdr.version != 0 {
                    return Err(Error::from_str("unsupported header version"));
                }

                if self.session.is_some()
                    && self.session.as_ref().unwrap().key.enc != hdr.key
                {
                    let _ = self.reset();
                }

                if self.session.is_none() {
                    self.init(hdr.algorithm, hdr.key)?;
                }

                let mut s = self.session.as_mut().unwrap();
                s.ctx = Some(support::decryption::init(
                    s.algo,
                    &s.key.raw,
                    hdr.iv,
                    if (hdr.flags & super::header::V0_FLAG_AAD) != 0 {
                        Some(&buf[0..hlen])
                    } else {
                        None
                    },
                )?);

                s.key.uses += 1;

                buf.drain(0..hlen);
            }
        }

        if self.session.is_some()
            && self.session.as_ref().unwrap().ctx.is_some()
        {
            let s = self.session.as_mut().unwrap();

            let sz: isize = buf.len() as isize - s.algo.len.tag as isize;
            if sz > 0 {
                let mut c = s.ctx.as_mut().unwrap();

                pt = support::decryption::update(
                    &mut c,
                    &buf[0..(sz as usize)],
                )?;

                buf.drain(0..(sz as usize));
            }
        }

        self.buf = buf;

        Ok(pt)
    }

    pub fn end(&mut self) -> Result<Vec<u8>> {
        let mut pt = Vec::<u8>::new();

        if self.session.is_some()
            && self.session.as_ref().unwrap().ctx.is_some()
        {
            let s = self.session.as_mut().unwrap();

            pt = support::decryption::finalize(
                s.ctx.as_mut().unwrap(),
                if self.buf.len() > 0 {
                    Some(&self.buf)
                } else {
                    None
                },
            )?;

            s.ctx = None;
            self.buf.truncate(0);
        }

        Ok(pt)
    }

    pub fn close(&mut self) -> Result<()> {
        self.reset()
    }

    fn init(&mut self, algo: usize, edk: &[u8]) -> Result<()> {
        let rsp = self.client.post(
            &format!("{}/{}", self.host, DECRYPTION_KEY_PATH),
            "application/json".to_string(),
            format!(
                "{{\
                   \"encrypted_data_key\": \"{}\"\
                 }}",
                support::base64::encode(edk)
            ),
        )?;

        match rsp.json::<NewDecryptionResponse>() {
            Err(e) => return Err(Error::from_string(e.to_string())),
            Ok(msg) => {
                self.session = Some(DecryptionSession {
                    id: msg.encryption_session,

                    key: DecryptionSessionKey {
                        raw: support::unwrap_data_key(
                            &support::base64::decode(&msg.wrapped_data_key)?,
                            &msg.encrypted_private_key,
                            &self.srsa,
                        )?,
                        enc: edk.to_vec(),

                        fingerprint: msg.key_fingerprint,

                        uses: 0,
                    },

                    algo: super::algorithm::get_by_id(algo)?,
                    ctx: None,
                });
            }
        }

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let session = std::mem::replace(&mut self.session, None);

        self.buf.truncate(0);

        if session.is_some() {
            let s = session.unwrap();

            if s.key.uses > 0 {
                let mut path = format!(
                    "{}/{}/{}",
                    self.host, DECRYPTION_KEY_PATH, s.key.fingerprint
                );
                if s.id.is_some() {
                    path = format!("{}/{}", path, s.id.as_ref().unwrap());
                }

                self.client.patch(
                    &path,
                    "application/json".to_string(),
                    format!(
                        "{{\
                           \"uses\": {}\
                         }}",
                        s.key.uses
                    ),
                )?;
            }
        }

        Ok(())
    }
}

impl Drop for Decryption<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub fn decrypt(c: &Credentials, ct: &[u8]) -> Result<Vec<u8>> {
    let mut dec = Decryption::new(&c)?;
    let mut pt: Vec<u8>;

    pt = dec.begin()?;
    pt.extend(dec.update(ct)?);
    pt.extend(dec.end()?);

    Ok(pt)
}

#[cfg(test)]
mod tests {
    #[test]
    fn simple_decrypt() {
        let pt = b"abc";

        let res = super::super::credentials::Credentials::new(None, None);
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        let creds = res.unwrap();

        let res = super::super::encryption::encrypt(&creds, &pt[..]);
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        let ct = res.unwrap();

        let res = super::super::decryption::decrypt(&creds, &ct);
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
        let rec = res.unwrap();

        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
    }
}
