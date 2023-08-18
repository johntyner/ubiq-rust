use super::error::Error;
use super::Result;

pub mod base64;
pub mod cipher;
pub mod digest;
pub mod encryption;
pub mod hmac;

pub fn getrandom(buf: &mut [u8]) -> Result<()> {
    match openssl::rand::rand_bytes(buf) {
        Err(e) => Err(Error::from_string(e.to_string())),
        Ok(_) => Ok(()),
    }
}

fn openssl_unwrap_data_key(
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

pub fn unwrap_data_key(wdk: &str, epk: &str, srsa: &str) -> Result<Vec<u8>> {
    let w = super::support::base64::decode(wdk)?;
    match openssl_unwrap_data_key(&w[..], epk, srsa) {
        Err(e) => Err(Error::from_string(e.to_string())),
        Ok(k) => Ok(k),
    }
}
