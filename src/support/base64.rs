pub fn decode(s: &str) -> crate::result::Result<Vec<u8>> {
    match openssl::base64::decode_block(s) {
        Err(e) => Err(crate::error::Error::from_string(e.to_string())),
        Ok(v) => Ok(v),
    }
}

pub fn encode(v: &[u8]) -> String {
    openssl::base64::encode_block(v)
}
