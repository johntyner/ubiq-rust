pub const V0_FLAG_AAD: usize = 1 << 0;

pub struct Header<'a> {
    version: usize,
    flags: usize,
    algorithm: usize,
    iv: &'a Vec<u8>,
    key: &'a Vec<u8>,
}

impl Header<'_> {
    pub fn new<'a>(
        flags: usize,
        algorithm: usize,
        iv: &'a Vec<u8>,
        key: &'a Vec<u8>,
    ) -> Header<'a> {
        Header {
            version: 0,
            flags: flags,
            algorithm: algorithm,
            iv: iv,
            key: key,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut v: Vec<u8> =
            Vec::with_capacity(6 + self.iv.len() + self.key.len());

        v.push(self.version as u8);
        v.push(self.flags as u8);
        v.push(self.algorithm as u8);
        v.push(self.iv.len() as u8);
        v.push((self.key.len() >> 8) as u8);
        v.push(self.key.len() as u8);
        v.extend(self.iv);
        v.extend(self.key);

        v
    }

    pub fn deserialize<'a>(_v: &'a [u8]) -> super::Result<Header<'a>> {
        Err(super::error::Error::from_str("not implemented"))
    }
}
