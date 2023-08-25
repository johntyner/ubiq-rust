use crate::error::Error;
use crate::result::Result;

pub struct DigestCtx {
    ctx: openssl::md_ctx::MdCtx,
}

impl DigestCtx {
    pub fn new(name: &str) -> Result<Self> {
        let md: &openssl::md::MdRef;
        match name {
            "sha512" => md = openssl::md::Md::sha512(),
            _ => return Err(Error::new("unsupported hash algorithm")),
        }

        let mut ctx = openssl::md_ctx::MdCtx::new()?;
        ctx.digest_init(md)?;

        Ok(Self { ctx: ctx })
    }

    pub fn update(&mut self, m: &[u8]) -> Result<()> {
        self.ctx.digest_update(m)?;
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        let mut s = Vec::<u8>::new();
        s.resize(self.ctx.size(), 0);

        let res = self.ctx.digest_final(&mut s);
        let _ = self.ctx.reset();

        res?;
        Ok(s)
    }
}
