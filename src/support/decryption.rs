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
        .decrypt_init(Some(ctx.cipher), Some(key), Some(iv))?;

    if algo.len.tag != 0 && aad.is_some() {
        ctx.ctx.cipher_update(aad.unwrap(), None)?;
    }

    Ok(ctx)
}

pub fn update(
    ctx: &mut support::cipher::CipherCtx,
    ct: &[u8],
) -> Result<Vec<u8>> {
    let mut pt = Vec::<u8>::new();
    ctx.ctx.cipher_update_vec(ct, &mut pt)?;
    Ok(pt)
}

pub fn finalize(
    ctx: &mut support::cipher::CipherCtx,
    tag: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut pt = Vec::<u8>::new();

    if tag.is_some() {
        ctx.ctx.set_tag(tag.unwrap())?;
    }

    ctx.ctx.cipher_final_vec(&mut pt)?;
    Ok(pt)
}
