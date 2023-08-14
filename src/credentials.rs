use super::error::Error;
use super::Result;

const PAPI_ID: &str = "ACCESS_KEY_ID";
const SAPI_ID: &str = "SECRET_SIGNING_KEY";
const SRSA_ID: &str = "SECRET_CRYPTO_ACCESS_KEY";
const HOST_ID: &str = "SERVER";

pub struct Credentials {
    params: std::collections::HashMap<String, String>,
}

impl Credentials {
    fn construct() -> Credentials {
        return Credentials {
            params: std::collections::HashMap::new(),
        };
    }

    pub fn new(
        path: Option<String>,
        prof: Option<String>,
    ) -> Result<Credentials> {
        Err(Error::from_str("not implemented"))
    }

    pub fn new_explicit(
        papi: String,
        sapi: String,
        srsa: String,
        host: Option<String>,
    ) -> Result<Credentials> {
        Err(Error::from_str("not implemented"))
    }

    fn papi(&self) -> Option<String> {
        return self.params.get(PAPI_ID).cloned();
    }

    fn sapi(&self) -> Option<String> {
        return self.params.get(SAPI_ID).cloned();
    }

    fn srsa(&self) -> Option<String> {
        return self.params.get(SRSA_ID).cloned();
    }

    fn host(&self) -> Option<String> {
        return self.params.get(HOST_ID).cloned();
    }
}
