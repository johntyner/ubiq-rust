use crate::error::Error;
use crate::result::Result;

pub enum CipherOp {
    Encrypt,
    Decrypt,
}

pub struct CipherCtx {
    op: CipherOp,
    ctx: openssl::cipher_ctx::CipherCtx,
}

impl std::fmt::Debug for CipherCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{{ ... }}")
    }
}

impl CipherCtx {
    pub fn new(
        op: CipherOp,
        name: &str,
        key: &[u8],
        iv: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<CipherCtx> {
        let ciph = match name {
            "aes-256-gcm" => openssl::cipher::Cipher::aes_256_gcm(),
            "aes-128-gcm" => openssl::cipher::Cipher::aes_128_gcm(),
            _ => {
                return Err(Error::new(&format!(
                    "unsupported algorithm: {}",
                    name
                )))
            }
        };

        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;

        match op {
            CipherOp::Encrypt => {
                ctx.encrypt_init(Some(ciph), Some(key), Some(iv))?
            }
            CipherOp::Decrypt => {
                ctx.decrypt_init(Some(ciph), Some(key), Some(iv))?
            }
        }

        if ctx.tag_length() > 0 && aad.is_some() {
            ctx.cipher_update(aad.unwrap(), None)?;
        }

        Ok(CipherCtx { op: op, ctx: ctx })
    }

    pub fn update(&mut self, inp: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::<u8>::new();
        self.ctx.cipher_update_vec(inp, &mut out)?;
        Ok(out)
    }

    pub fn finalize(&mut self, tag: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut out = Vec::<u8>::new();

        match self.op {
            CipherOp::Encrypt => {
                let len = self.ctx.cipher_final_vec(&mut out)?;

                if self.ctx.tag_length() > 0 {
                    out.resize(len + self.ctx.tag_length(), 0);
                    self.ctx.tag(&mut out[len..])?;
                }
            }
            CipherOp::Decrypt => {
                if tag.is_some() {
                    self.ctx.set_tag(tag.unwrap())?;
                }

                self.ctx.cipher_final_vec(&mut out)?;
            }
        }

        Ok(out)
    }
}
