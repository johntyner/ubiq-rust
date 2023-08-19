pub fn init<'a>(
    algo: &'a super::super::algorithm::Algorithm<'a>,
    key: &[u8],
    iv: &[u8],
    aad: Option<&[u8]>,
) -> super::Result<super::cipher::CipherCtx<'a>> {
    let mut ctx = super::cipher::CipherCtx::new(algo)?;

    let res = ctx.ctx.decrypt_init(Some(ctx.cipher), Some(key), Some(iv));
    if res.is_err() {
        return Err(super::Error::from_string(res.unwrap_err().to_string()));
    }

    if algo.len.tag != 0 && aad.is_some() {
        let res = ctx.ctx.cipher_update(aad.unwrap(), None);
        if res.is_err() {
            return Err(super::Error::from_string(
                res.unwrap_err().to_string(),
            ));
        }
    }

    Ok(ctx)
}

pub fn update(
    ctx: &mut super::cipher::CipherCtx,
    ct: &[u8],
) -> super::Result<Vec<u8>> {
    let mut pt = Vec::<u8>::new();

    match ctx.ctx.cipher_update_vec(ct, &mut pt) {
        Err(e) => Err(super::Error::from_string(e.to_string())),
        Ok(_) => Ok(pt),
    }
}

pub fn finalize(
    ctx: &mut super::cipher::CipherCtx,
    tag: Option<&[u8]>,
) -> super::Result<Vec<u8>> {
    let mut pt = Vec::<u8>::new();

    if tag.is_some() {
        match ctx.ctx.set_tag(tag.unwrap()) {
            Err(e) => return Err(super::Error::from_string(e.to_string())),
            Ok(_) => (),
        }
    }

    match ctx.ctx.cipher_final_vec(&mut pt) {
        Err(e) => return Err(super::Error::from_string(e.to_string())),
        Ok(_) => Ok(pt),
    }
}
