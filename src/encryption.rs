use super::client::Client;
use super::credentials::Credentials;
use super::error::Error;
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

struct EncryptionKeyUses {
    max: usize,
    cur: usize,
}

struct EncryptionKey {
    raw: Vec<u8>,
    enc: Vec<u8>,
    fingerprint: String,
    uses: EncryptionKeyUses,
}

struct Encryption<'a> {
    client: Client,
    host: String,

    session: String,

    key: EncryptionKey,

    algo: &'a super::algorithm::Algorithm<'a>,
}

const ENCRYPTION_KEY_PATH: &str = "api/v0/encryption/key";

fn support_unwrap_data_key(
    wdk: &[u8],
    epk: &str,
    srsa: &str,
) -> core::result::Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut raw: Vec<u8> = Vec::new();

    let pk = openssl::pkey::PKey::private_key_from_pem_passphrase(
        epk.as_bytes(),
        srsa.as_bytes(),
    )?;

    let mut pk_ctx = openssl::pkey_ctx::PkeyCtx::new(&pk)?;
    pk_ctx.decrypt_init()?;
    pk_ctx.set_rsa_oaep_md(&openssl::md::Md::sha1())?;
    pk_ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
    pk_ctx.decrypt_to_vec(wdk, &mut raw)?;

    Ok(raw)
}

fn unwrap_data_key(wdk: &str, epk: &str, srsa: &str) -> Result<Vec<u8>> {
    let w = super::base64::decode(wdk)?;
    match support_unwrap_data_key(&w[..], epk, srsa) {
        Err(e) => Err(Error::from_string(e.to_string())),
        Ok(k) => Ok(k),
    }
}

impl Encryption<'_> {
    pub fn new(creds: &Credentials, uses: u32) -> Result<Encryption> {
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

        Ok(Encryption {
            client: client,
            host: host,

            session: msg.encryption_session,

            key: EncryptionKey {
                enc: super::base64::decode(&msg.encrypted_data_key)?,
                raw: unwrap_data_key(
                    &msg.wrapped_data_key,
                    &msg.encrypted_private_key,
                    &creds.srsa(),
                )?,

                fingerprint: msg.key_fingerprint,

                uses: EncryptionKeyUses {
                    max: msg.max_uses,
                    cur: 0,
                },
            },

            algo: super::algorithm::get_by_name(&msg.security_model.algorithm)?,
        })
    }

    pub fn close(&mut self) -> Result<()> {
        let cur = self.key.uses.cur;
        let max = self.key.uses.max;

        self.key.uses.cur = 0;
        self.key.uses.max = 0;

        if cur < max {
            self.client.patch(
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
        }

        Ok(())
    }
}

impl Drop for Encryption<'_> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::Encryption;
    use crate::credentials::Credentials;

    fn new_encryption(uses: u32) -> Encryption {
        let res = Credentials::new(None, None);
        unsafe {
            assert!(res.is_ok(), "{}", res.unwrap_err_unchecked().to_string());
        }
        let creds = res.unwrap();

        let res = Encryption::new(&creds, uses);
        unsafe {
            assert!(res.is_ok(), "{}", res.unwrap_err_unchecked().to_string());
        }
        res.unwrap()
    }

    #[test]
    fn no_encryption() {
        let mut enc = new_encryption(1);
        let res = enc.close();
        assert!(res.is_ok(), "{}", res.unwrap_err().to_string());
    }
}
