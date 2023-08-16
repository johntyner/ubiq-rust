use super::error::Error;
use super::Result;

struct AlgorithmLengths {
    key: u32,
    iv: u32,
    tag: u32,
}

pub struct Algorithm<'a> {
    id: usize,
    name: &'a str,

    len: AlgorithmLengths,
}

const ALGORITHM: &'static [Algorithm] = &[
    Algorithm {
        id: 0,
        name: "aes-256-gcm",
        len: AlgorithmLengths {
            key: 32,
            iv: 12,
            tag: 16,
        },
    },
    Algorithm {
        id: 1,
        name: "aes-128-gcm",
        len: AlgorithmLengths {
            key: 16,
            iv: 12,
            tag: 16,
        },
    },
];

pub fn get_by_id(id: usize) -> Result<&'static Algorithm<'static>> {
    if id < ALGORITHM.len() && id == ALGORITHM[id].id {
        return Ok(&ALGORITHM[id]);
    }

    Err(Error::from_str("algorithm id not found"))
}

pub fn get_by_name(name: &str) -> Result<&'static Algorithm<'static>> {
    for a in ALGORITHM {
        if name == a.name {
            return Ok(a);
        }
    }

    Err(Error::from_str("algorithm name not found"))
}
