use crate::error::Error;
use crate::result::Result;

pub struct HmacCtx {
    ctx: openssl::md_ctx::MdCtx,
}

impl HmacCtx {
    pub fn new(name: &str, key: &[u8]) -> Result<Self> {
        let mut ctx: openssl::md_ctx::MdCtx;
        let md: &openssl::md::MdRef;
        let pk: openssl::pkey::PKey<openssl::pkey::Private>;

        match name {
            "sha512" => md = openssl::md::Md::sha512(),
            _ => return Err(Error::from_str("unsupported hash algorithm")),
        }

        match openssl::md_ctx::MdCtx::new() {
            Err(e) => return Err(Error::from_string(e.to_string())),
            Ok(c) => ctx = c,
        }

        match openssl::pkey::PKey::hmac(key) {
            Err(e) => return Err(Error::from_string(e.to_string())),
            Ok(k) => pk = k,
        }

        match ctx.digest_sign_init(Some(md), &pk) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(_) => Ok(Self { ctx: ctx }),
        }
    }

    pub fn update(&mut self, m: &[u8]) -> Result<()> {
        match self.ctx.digest_sign_update(m) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(_) => Ok(()),
        }
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        let mut s = Vec::<u8>::new();

        let res = self.ctx.digest_sign_final_to_vec(&mut s);
        let _ = self.ctx.reset();

        match res {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(_) => Ok(s),
        }
    }
}
