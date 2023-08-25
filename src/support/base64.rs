pub fn decode(s: &str) -> crate::result::Result<Vec<u8>> {
    Ok(openssl::base64::decode_block(s)?)
}

pub fn encode(v: &[u8]) -> String {
    openssl::base64::encode_block(v)
}
