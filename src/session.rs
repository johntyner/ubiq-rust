use crate::algorithm::Algorithm;
use crate::base64;
use crate::cipher;
use crate::client::Client;
use crate::result::Result;

use rsa::pkcs8::DecodePrivateKey;

#[derive(Debug)]
pub(crate) struct SessionKeyUses {
    pub max: usize,
    pub cur: usize,
}

#[derive(Debug)]
pub(crate) struct SessionKey {
    pub raw: Vec<u8>,
    pub enc: Vec<u8>,

    pub fingerprint: String,

    pub uses: SessionKeyUses,
}

pub(crate) struct Session<'a> {
    client: std::rc::Rc<Client>,
    host: std::rc::Rc<String>,

    id: Option<String>,

    pub key: SessionKey,

    pub algo: &'a Algorithm<'a>,
    pub ctx: Option<cipher::CipherCtx>,

    close: fn(
        &Client,
        &String,
        &Option<String>,
        &String,
        &SessionKeyUses,
    ) -> Result<()>,
}

impl std::fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "")
    }
}

impl Session<'_> {
    pub fn new<'a>(
        client: std::rc::Rc<Client>,
        host: std::rc::Rc<String>,
        id: Option<String>,
        key_fp: &str,
        algo: &'a Algorithm<'a>,
        epk: &str,
        wdk: &str,
        edk: &str,
        uses: usize,
        srsa: &str,
        close: fn(
            &Client,
            &String,
            &Option<String>,
            &String,
            &SessionKeyUses,
        ) -> Result<()>,
    ) -> Result<Session<'a>> {
        Ok(Session {
            client: client,
            host: host,

            id: id,

            key: SessionKey {
                raw: rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(
                    epk,
                    srsa.as_bytes(),
                )?
                .decrypt(
                    rsa::oaep::Oaep::new::<sha1::Sha1>(),
                    &base64::decode(wdk)?,
                )?,
                enc: base64::decode(edk)?,

                fingerprint: key_fp.to_string(),

                uses: SessionKeyUses { max: uses, cur: 0 },
            },

            algo: algo,
            ctx: None,

            close: close,
        })
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        let _ = (self.close)(
            &self.client,
            &self.host,
            &self.id,
            &self.key.fingerprint,
            &self.key.uses,
        );
    }
}
