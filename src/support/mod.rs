use crate::result::Result;

pub mod base64;
pub mod cipher;
pub mod decryption;
pub mod encryption;

use rand::RngCore;
use rsa::pkcs8::DecodePrivateKey;

pub fn getrandom(buf: &mut [u8]) -> Result<()> {
    Ok(rand::thread_rng().fill_bytes(buf))
}

pub fn unwrap_data_key(wdk: &[u8], epk: &str, srsa: &str) -> Result<Vec<u8>> {
    Ok(
        rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(epk, srsa.as_bytes())?
            .decrypt(rsa::oaep::Oaep::new::<sha1::Sha1>(), wdk)?,
    )
}
