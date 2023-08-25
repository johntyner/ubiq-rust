use crate::result::Result;

pub mod base64;
pub mod cipher;
pub mod decryption;
pub mod encryption;
pub mod hmac;

pub fn getrandom(buf: &mut [u8]) -> Result<()> {
    Ok(openssl::rand::rand_bytes(buf)?)
}

pub fn unwrap_data_key(wdk: &[u8], epk: &str, srsa: &str) -> Result<Vec<u8>> {
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
