use crate::error::Error;
use crate::result::Result;

pub struct HmacCtx {
    ctx: openssl::md_ctx::MdCtx,
}

impl HmacCtx {
    pub fn new(name: &str, key: &[u8]) -> Result<Self> {
        let md: &openssl::md::MdRef;
        match name {
            "sha512" => md = openssl::md::Md::sha512(),
            _ => return Err(Error::new("unsupported hash algorithm")),
        }

        let mut ctx = openssl::md_ctx::MdCtx::new()?;
        let pk = openssl::pkey::PKey::hmac(key)?;
        ctx.digest_sign_init(Some(md), &pk)?;

        Ok(Self { ctx: ctx })
    }

    pub fn update(&mut self, m: &[u8]) -> Result<()> {
        self.ctx.digest_sign_update(m)?;
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        let mut s = Vec::<u8>::new();

        let res = self.ctx.digest_sign_final_to_vec(&mut s);
        let _ = self.ctx.reset();

        res?;
        Ok(s)
    }
}
