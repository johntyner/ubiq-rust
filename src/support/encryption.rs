use crate::result::Result;
use crate::support;

pub fn init<'a>(
    algo: &'a crate::algorithm::Algorithm<'a>,
    key: &[u8],
    iv: &[u8],
    aad: Option<&[u8]>,
) -> Result<support::cipher::CipherCtx<'a>> {
    let mut ctx = support::cipher::CipherCtx::new(algo)?;

    ctx.ctx
        .encrypt_init(Some(ctx.cipher), Some(key), Some(iv))?;

    if algo.len.tag != 0 && aad.is_some() {
        ctx.ctx.cipher_update(aad.unwrap(), None)?;
    }

    Ok(ctx)
}

pub fn update(
    ctx: &mut support::cipher::CipherCtx,
    pt: &[u8],
) -> Result<Vec<u8>> {
    let mut ct = Vec::<u8>::new();
    ctx.ctx.cipher_update_vec(pt, &mut ct)?;
    Ok(ct)
}

pub fn finalize(ctx: &mut support::cipher::CipherCtx) -> Result<Vec<u8>> {
    let mut ct = Vec::<u8>::new();
    let s = ctx.ctx.cipher_final_vec(&mut ct)?;

    if ctx.ctx.tag_length() > 0 {
        ct.resize(s + ctx.ctx.tag_length(), 0);
        ctx.ctx.tag(&mut ct[s..])?;
    }

    Ok(ct)
}
