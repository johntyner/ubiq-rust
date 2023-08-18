use super::error::Error;
use super::Result;

pub mod base64;
pub mod encryption;

pub struct CipherCtx<'a> {
    algo: &'a super::algorithm::Algorithm<'a>,
    cipher: &'a openssl::cipher::CipherRef,
    ctx: openssl::cipher_ctx::CipherCtx,
}

impl std::fmt::Debug for CipherCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(f, "{:?}", self.algo);
    }
}

impl CipherCtx<'_> {
    fn new<'a>(
        algo: &'a super::algorithm::Algorithm<'a>,
    ) -> Result<CipherCtx<'a>> {
        let c: &openssl::cipher::CipherRef;
        match algo.name {
            "aes-256-gcm" => c = openssl::cipher::Cipher::aes_256_gcm(),
            "aes-128-gcm" => c = openssl::cipher::Cipher::aes_128_gcm(),
            _ => {
                return Err(Error::from_string(format!(
                    "unsupported algorithm: {}",
                    algo.name
                )))
            }
        }

        let ctx: openssl::cipher_ctx::CipherCtx;
        match openssl::cipher_ctx::CipherCtx::new() {
            Err(e) => return Err(Error::from_string(e.to_string())),
            Ok(c) => ctx = c,
        }

        Ok(CipherCtx {
            algo: algo,
            cipher: c,
            ctx: ctx,
        })
    }
}

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
