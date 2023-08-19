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
    client: std::rc::Rc<Client>,
    host: std::rc::Rc<String>,

    id: Option<String>,

    key: DecryptionSessionKey,

    algo: &'a Algorithm<'a>,
    ctx: Option<support::cipher::CipherCtx<'a>>,
}

impl DecryptionSession<'_> {
    fn new<'a>(
        client: std::rc::Rc<Client>,
        host: std::rc::Rc<String>,
        algo: usize,
        edk: &[u8],
        srsa: &str,
    ) -> Result<DecryptionSession<'a>> {
        let rsp = client.post(
            &format!("{}/{}", host, DECRYPTION_KEY_PATH),
            "application/json".to_string(),
            format!(
                "{{\
                   \"encrypted_data_key\": \"{}\"\
                 }}",
                support::base64::encode(edk)
            ),
        )?;

        match rsp.json::<NewDecryptionResponse>() {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(msg) => Ok(DecryptionSession {
                client: client,
                host: host,

                id: msg.encryption_session,

                key: DecryptionSessionKey {
                    raw: support::unwrap_data_key(
                        &support::base64::decode(&msg.wrapped_data_key)?,
                        &msg.encrypted_private_key,
                        srsa,
                    )?,
                    enc: edk.to_vec(),

                    fingerprint: msg.key_fingerprint,

                    uses: 0,
                },

                algo: super::algorithm::get_by_id(algo)?,
                ctx: None,
            }),
        }
    }

    fn close(&mut self) -> Result<()> {
        if self.key.uses > 0 {
            let mut path = format!(
                "{}/{}/{}",
                self.host, DECRYPTION_KEY_PATH, self.key.fingerprint
            );
            if self.id.is_some() {
                path = format!("{}/{}", path, self.id.as_ref().unwrap());
            }

            self.client.patch(
                &path,
                "application/json".to_string(),
                format!(
                    "{{\
                       \"uses\": {}\
                     }}",
                    self.key.uses
                ),
            )?;
        }

        Ok(())
    }
}

impl Drop for DecryptionSession<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub struct Decryption<'a> {
    client: std::rc::Rc<Client>,
    host: std::rc::Rc<String>,

    srsa: String,
    session: Option<DecryptionSession<'a>>,

    buf: Vec<u8>,
}

const DECRYPTION_KEY_PATH: &str = "api/v0/decryption/key";

impl Decryption<'_> {
    pub fn new<'a>(creds: &Credentials) -> Result<Decryption<'a>> {
        Ok(Decryption {
            client: std::rc::Rc::new(Client::new(creds)),
            host: std::rc::Rc::new(creds.host().clone()),

            srsa: creds.srsa().clone(),
            session: None,

            buf: Vec::new(),
        })
    }

    pub fn begin(&mut self) -> Result<Vec<u8>> {
        if self.session.is_some()
            && self.session.as_ref().unwrap().ctx.is_some()
        {
            return Err(Error::from_str("decryption already in progress"));
        }

        Ok(Vec::<u8>::new())
    }

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
                    return Err(Error::from_str("unsupported header version"));
                }

                if self.session.is_some()
                    && self.session.as_ref().unwrap().key.enc != hdr.key
                {
                    self.session = None;
                }

                if self.session.is_none() {
                    self.session = Some(DecryptionSession::new(
                        std::rc::Rc::clone(&self.client),
                        std::rc::Rc::clone(&self.host),
                        hdr.algorithm,
                        hdr.key,
                        &self.srsa,
                    )?);
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

                pt = support::decryption::update(
                    &mut s.ctx.as_mut().unwrap(),
                    &self.buf[0..sz],
                )?;

                self.buf.drain(0..sz);
            }
        }

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

            self.buf.truncate(0);
            s.ctx = None;
        }

        Ok(pt)
    }

    pub fn close(&mut self) -> Result<()> {
        let session = std::mem::replace(&mut self.session, None);
        match session {
            Some(mut s) => s.close(),
            None => Ok(()),
        }
    }

    pub fn cipher(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let mut pt = self.begin()?;
        pt.extend(self.update(ct)?);
        pt.extend(self.end()?);
        Ok(pt)
    }
}

impl Drop for Decryption<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub fn decrypt(c: &Credentials, ct: &[u8]) -> Result<Vec<u8>> {
    Decryption::new(&c)?.cipher(&ct)
}

#[cfg(test)]
mod tests {
    #[test]
    fn reuse_session() -> super::super::Result<()> {
        let pt = b"abc";

        let creds = super::super::credentials::Credentials::new(None, None)?;
        let ct = super::super::encryption::encrypt(&creds, &pt[..])?;
        let mut dec = super::Decryption::new(&creds)?;

        let rec = dec.cipher(&ct)?;
        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
        let fp1 = dec.session.as_ref().unwrap().key.fingerprint.clone();
        let s1 = dec.session.as_ref().unwrap()
            as *const super::DecryptionSession<'_>;

        let rec = dec.cipher(&ct)?;
        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
        let fp2 = dec.session.as_ref().unwrap().key.fingerprint.clone();
        let s2 = dec.session.as_ref().unwrap()
            as *const super::DecryptionSession<'_>;

        /*
         * we really want to compare the session.id, but
         * the server is currently returning `null` in that
         * field which in unhelpful.
         */
        assert!(fp1 == fp2 && s1 == s2);

        Ok(())
    }

    #[test]
    fn change_session() -> super::super::Result<()> {
        let pt = b"abc";

        let creds = super::super::credentials::Credentials::new(None, None)?;
        let mut dec = super::Decryption::new(&creds)?;

        let ct = super::super::encryption::encrypt(&creds, &pt[..])?;
        let rec = dec.cipher(&ct)?;
        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
        let fp1 = dec.session.as_ref().unwrap().key.fingerprint.clone();

        let ct = super::super::encryption::encrypt(&creds, &pt[..])?;
        let rec = dec.cipher(&ct)?;
        assert!(pt[..] == rec, "{}", "recovered plaintext does not match");
        let fp2 = dec.session.as_ref().unwrap().key.fingerprint.clone();

        /* different key fingerprints means different sessions */
        assert!(fp1 != fp2);

        Ok(())
    }
}
