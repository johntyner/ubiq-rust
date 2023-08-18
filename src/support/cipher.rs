use super::Error;
use super::Result;

pub struct CipherCtx<'a> {
    pub(super) algo: &'a super::super::algorithm::Algorithm<'a>,
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
        algo: &'a super::super::algorithm::Algorithm<'a>,
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
