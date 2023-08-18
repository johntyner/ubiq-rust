pub fn init<'a>(
    algo: &'a super::super::algorithm::Algorithm<'a>,
    key: &[u8],
    iv: &[u8],
    aad: Option<&[u8]>,
) -> super::Result<super::cipher::CipherCtx<'a>> {
    let mut ctx = super::cipher::CipherCtx::new(algo)?;

    let res = ctx.ctx.encrypt_init(Some(ctx.cipher), Some(key), Some(iv));
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
    pt: &[u8],
) -> super::Result<Vec<u8>> {
    let mut ct = Vec::<u8>::new();

    match ctx.ctx.cipher_update_vec(pt, &mut ct) {
        Err(e) => Err(super::Error::from_string(e.to_string())),
        Ok(_) => Ok(ct),
    }
}

pub fn finalize(ctx: &mut super::cipher::CipherCtx) -> super::Result<Vec<u8>> {
    let mut ct = Vec::<u8>::new();

    match ctx.ctx.cipher_final_vec(&mut ct) {
        Err(e) => return Err(super::Error::from_string(e.to_string())),
        Ok(s) => {
            if ctx.ctx.tag_length() > 0 {
                ct.resize(s + ctx.ctx.tag_length(), 0);
                let res = ctx.ctx.tag(&mut ct[s..]);
                if res.is_err() {
                    return Err(super::Error::from_string(
                        res.unwrap_err().to_string(),
                    ));
                }
            }
        }
    }

    Ok(ct)
}
