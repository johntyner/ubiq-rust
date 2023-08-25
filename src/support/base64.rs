use base64::Engine;

pub fn decode(s: &str) -> crate::result::Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

pub fn encode(v: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}
