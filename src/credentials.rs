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
    fn get_default_filepath() -> Result<String> {
        let path: String;

        match dirs::home_dir() {
            None => {
                return Err(Error::from_str(
                    "unable to determine home directory",
                ));
            }
            Some(mut home) => {
                home.push(".ubiq");
                home.push("credentials");

                match home.to_str() {
                    None => {
                        return Err(Error::from_str(
                            "unable to convert path to string, non-UTF-8?",
                        ));
                    }
                    Some(fp) => path = fp.to_string(),
                }
            }
        }

        Ok(path)
    }

    fn construct() -> Credentials {
        return Credentials {
            params: std::collections::HashMap::new(),
        };
    }

    pub fn new(
        opt_path: Option<String>,
        opt_prof: Option<String>,
    ) -> Result<Credentials> {
        let path: String;
        let prof: String;

        match opt_path {
            Some(p) => path = p,
            None => {
                match Self::get_default_filepath() {
                    Ok(p) => path = p,
                    Err(e) => return Err(e),
                }
            }
        }

        match opt_prof {
            Some(p) => prof = p,
            None => prof = "default".to_string(),
        }

        Err(Error::from_str("not implemented"))
    }

    pub fn create(
        papi: String,
        sapi: String,
        srsa: String,
        opt_host: Option<String>,
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
