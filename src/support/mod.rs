use crate::result::Result;

pub mod base64;
pub mod cipher;
pub mod decryption;
pub mod encryption;

use rsa::pkcs8::DecodePrivateKey;
use rand::RngCore;

pub fn getrandom(buf: &mut [u8]) -> Result<()> {
    Ok(rand::thread_rng().fill_bytes(buf))
}

pub fn unwrap_data_key(wdk: &[u8], epk: &str, srsa: &str) -> Result<Vec<u8>> {
    let mut raw: Vec<u8> = Vec::new();

    if false {
        let pk = rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(
            epk, srsa.as_bytes())?;

        raw = pk.decrypt(rsa::oaep::Oaep::new::<sha1::Sha1>(), wdk)?;
    } else {

        let pk = openssl::pkey::PKey::private_key_from_pem_passphrase(
            epk.as_bytes(),
            srsa.as_bytes(),
        )?;

        let mut pk_ctx = openssl::pkey_ctx::PkeyCtx::new(&pk)?;
        pk_ctx.decrypt_init()?;
        pk_ctx.set_rsa_oaep_md(&openssl::md::Md::sha1())?;
        pk_ctx.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
        pk_ctx.decrypt_to_vec(wdk, &mut raw)?;
    }

    Ok(raw)
}
