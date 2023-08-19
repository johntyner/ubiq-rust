use crate::error::Error;
use crate::result::Result;

pub struct DigestCtx {
    ctx: openssl::md_ctx::MdCtx,
}

impl DigestCtx {
    pub fn new(name: &str) -> Result<Self> {
        let mut ctx: openssl::md_ctx::MdCtx;
        let md: &openssl::md::MdRef;

        match name {
            "sha512" => md = openssl::md::Md::sha512(),
            _ => return Err(Error::from_str("unsupported hash algorithm")),
        }

        match openssl::md_ctx::MdCtx::new() {
            Err(e) => return Err(Error::from_string(e.to_string())),
            Ok(c) => ctx = c,
        }

        match ctx.digest_init(md) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(_) => Ok(Self { ctx: ctx }),
        }
    }

    pub fn update(&mut self, m: &[u8]) -> Result<()> {
        match self.ctx.digest_update(m) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(_) => Ok(()),
        }
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        let mut s = Vec::<u8>::new();
        s.resize(self.ctx.size(), 0);

        let res = self.ctx.digest_final(&mut s);
        let _ = self.ctx.reset();

        match res {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(_) => Ok(s),
        }
    }
}
