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
                    Some(ref fp) => path = fp.to_string(),
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
        let mut ini = configparser::ini::Ini::new_cs();

        let path: String;
        let prof: String;
        let conf: &std::collections::HashMap<
            String,
            std::collections::HashMap<String, Option<String>>,
        >;

        match opt_path {
            Some(p) => path = p,
            None => match Self::get_default_filepath() {
                Ok(p) => path = p,
                Err(e) => return Err(e),
            },
        }

        match opt_prof {
            Some(p) => prof = p,
            None => prof = "default".to_string(),
        }

        match ini.load(path.as_str()) {
            Err(ref s) => return Err(Error::from_string(s.clone())),
            Ok(ref map) => conf = map,
        }

        Err(Error::from_str("not implemented"))
    }

    pub fn create(
        papi: String,
        sapi: String,
        srsa: String,
        opt_host: Option<&String>,
    ) -> Result<Credentials> {
        let mut c = Self::construct();
        let mut host: String;

        match opt_host {
            None => host = "api.ubiqsecurity.com".to_string(),
            Some(h) => host = h.clone(),
        }

        if !host.starts_with("http://") && !host.starts_with("https://") {
            host.insert_str(0, "https://");
        }

        c.params.insert(PAPI_ID.to_string(), papi);
        c.params.insert(SAPI_ID.to_string(), sapi);
        c.params.insert(SRSA_ID.to_string(), srsa);
        c.params.insert(HOST_ID.to_string(), host);

        Ok(c)
    }

    fn papi(&self) -> Option<&String> {
        return self.params.get(PAPI_ID);
    }

    fn sapi(&self) -> Option<&String> {
        return self.params.get(SAPI_ID);
    }

    fn srsa(&self) -> Option<&String> {
        return self.params.get(SRSA_ID);
    }

    fn host(&self) -> Option<&String> {
        return self.params.get(HOST_ID);
    }
}
