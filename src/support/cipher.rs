use crate::error::Error;
use crate::result::Result;

pub struct CipherCtx<'a> {
    pub(super) algo: &'a crate::algorithm::Algorithm<'a>,
    pub(super) cipher: &'a openssl::cipher::CipherRef,
    pub(super) ctx: openssl::cipher_ctx::CipherCtx,
}

impl std::fmt::Debug for CipherCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(f, "{:?}", self.algo);
    }
}

impl CipherCtx<'_> {
    pub fn new<'a>(
        algo: &'a crate::algorithm::Algorithm<'a>,
    ) -> Result<CipherCtx<'a>> {
        let c: &openssl::cipher::CipherRef;
        match algo.name {
            "aes-256-gcm" => c = openssl::cipher::Cipher::aes_256_gcm(),
            "aes-128-gcm" => c = openssl::cipher::Cipher::aes_128_gcm(),
            _ => {
                return Err(Error::new(&format!(
                    "unsupported algorithm: {}",
                    algo.name
                )))
            }
        }

        Ok(CipherCtx {
            algo: algo,
            cipher: c,
            ctx: openssl::cipher_ctx::CipherCtx::new()?,
        })
    }
}
