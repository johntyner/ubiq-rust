use crate::error::Error;
use crate::result::Result;

pub const V0_FLAG_AAD: usize = 1 << 0;

pub struct Header<'a> {
    pub(crate) version: usize,
    pub(crate) flags: usize,
    pub(crate) algorithm: usize,
    pub(crate) iv: &'a [u8],
    pub(crate) key: &'a [u8],
}

impl Header<'_> {
    pub fn new<'a>(
        flags: usize,
        algorithm: usize,
        iv: &'a [u8],
        key: &'a [u8],
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

    pub fn can_deserialize(v: &[u8]) -> Result<usize> {
        if v.len() > 0 && v[0] != 0 {
            return Err(Error::new("invalid header version"));
        }

        if v.len() < 6 {
            return Ok(0);
        }

        let ivlen: u8 = v[3];
        let keylen = (((v[4] as u16) << 8) | (v[5] as u16)) as usize;
        let hsize: usize = 6 + ivlen as usize + keylen as usize;

        if v.len() < hsize {
            return Ok(0);
        }

        Ok(hsize)
    }

    pub fn deserialize<'a>(v: &'a [u8]) -> Result<Header<'a>> {
        let ivlen = v[3] as usize;
        let keylen = (((v[4] as u16) << 8) | (v[5] as u16)) as usize;

        Ok(Header {
            version: v[0] as usize,
            flags: v[1] as usize,
            algorithm: v[2] as usize,
            iv: &v[6..(6 + ivlen)],
            key: &v[(6 + ivlen)..(6 + ivlen + keylen)],
        })
    }
}
