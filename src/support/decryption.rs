use crate::error::Error;
use crate::result::Result;
use crate::support;

pub fn init<'a>(
    algo: &'a crate::algorithm::Algorithm<'a>,
    key: &[u8],
    iv: &[u8],
    aad: Option<&[u8]>,
) -> Result<support::cipher::CipherCtx<'a>> {
    let mut ctx = support::cipher::CipherCtx::new(algo)?;

    let res = ctx.ctx.decrypt_init(Some(ctx.cipher), Some(key), Some(iv));
    if res.is_err() {
        return Err(Error::from_string(res.unwrap_err().to_string()));
    }

    if algo.len.tag != 0 && aad.is_some() {
        let res = ctx.ctx.cipher_update(aad.unwrap(), None);
        if res.is_err() {
            return Err(Error::from_string(res.unwrap_err().to_string()));
        }
    }

    Ok(ctx)
}

pub fn update(
    ctx: &mut support::cipher::CipherCtx,
    ct: &[u8],
) -> Result<Vec<u8>> {
    let mut pt = Vec::<u8>::new();

    match ctx.ctx.cipher_update_vec(ct, &mut pt) {
        Err(e) => Err(Error::from_string(e.to_string())),
        Ok(_) => Ok(pt),
    }
}

pub fn finalize(
    ctx: &mut support::cipher::CipherCtx,
    tag: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut pt = Vec::<u8>::new();

    if tag.is_some() {
        match ctx.ctx.set_tag(tag.unwrap()) {
            Err(e) => return Err(Error::from_string(e.to_string())),
            Ok(_) => (),
        }
    }

    match ctx.ctx.cipher_final_vec(&mut pt) {
        Err(e) => return Err(Error::from_string(e.to_string())),
        Ok(_) => Ok(pt),
    }
}
