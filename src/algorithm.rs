use super::error::Error;
use super::Result;

pub struct AlgorithmLengths {
    pub key: usize,
    pub iv: usize,
    pub tag: usize,
}

pub struct Algorithm<'a> {
    pub id: usize,
    pub name: &'a str,

    pub len: AlgorithmLengths,
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
    let n = name.to_lowercase();

    for a in ALGORITHM {
        if n == a.name {
            return Ok(a);
        }
    }

    Err(Error::from_str("algorithm name not found"))
}
