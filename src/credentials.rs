use crate::error::Error;
use crate::result::Result;

const PAPI_ID: &str = "ACCESS_KEY_ID";
const SAPI_ID: &str = "SECRET_SIGNING_KEY";
const SRSA_ID: &str = "SECRET_CRYPTO_ACCESS_KEY";
const HOST_ID: &str = "SERVER";

const ENV_PREFIX: &str = "UBIQ_";

const SERVER: &str = "api.ubiqsecurity.com";

const MAX_CREDENTIALS_SIZE: usize = 1024;

#[derive(Debug)]
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

    fn from_env() -> Credentials {
        let mut c = Self::construct();

        for s in [PAPI_ID, SAPI_ID, SRSA_ID, HOST_ID] {
            let k = format!("{}{}", ENV_PREFIX, s);

            match std::env::var_os(k.clone()) {
                None => (),
                Some(v) => match v.to_str() {
                    None => (),
                    Some(val) => {
                        c.params.insert(s.to_string(), val.to_string());
                    }
                },
            }
        }

        c
    }

    fn from_string(input: String, prof: &String) -> Result<Credentials> {
        let mut c = Self::construct();
        let mut ini = configparser::ini::Ini::new_cs();

        // todo separate loading from file and parsing so that
        // parsing can be unit tested more easily
        match ini.read(input) {
            Err(s) => return Err(Error::from_string(s)),
            Ok(profs) => match profs.get(prof) {
                None => {
                    return Err(Error::from_str("specified profile not found"))
                }
                Some(creds) => {
                    for k in [PAPI_ID, SAPI_ID, SRSA_ID, HOST_ID] {
                        let v = creds.get(k);
                        /*
                         * this is kinda nasty:
                         * creds is a HashMap<String, Option<String>>,
                         * so the creds.get() returns an Option<Option<String>>
                         *
                         * the first option tells us whether k even exists
                         * if it does, then the value could be None or a string,
                         * hence the second Option
                         *
                         * i suppose it could be a parse error if the second
                         * Option is None, but that's a problem for another
                         * time. for now, ignore it.
                         */
                        if v.is_some() && v.unwrap().is_some() {
                            c.params.insert(
                                k.to_string(),
                                v.unwrap().as_ref().unwrap().to_string(),
                            );
                        }
                    }
                }
            },
        }

        Ok(c)
    }

    fn from_file(path: &String, prof: &String) -> Result<Credentials> {
        match std::fs::metadata(path) {
            Err(e) => return Err(Error::from_string(e.to_string())),
            Ok(m) => {
                if m.len() > MAX_CREDENTIALS_SIZE as u64 {
                    return Err(Error::from_str("credentials file too big"));
                }
            }
        }

        match std::fs::read(path) {
            Err(e) => Err(Error::from_string(e.to_string())),
            Ok(v) => match String::from_utf8(v) {
                Err(e) => Err(Error::from_string(e.to_string())),
                Ok(s) => Self::from_string(s, prof),
            },
        }
    }

    pub fn new(
        opt_path: Option<String>,
        opt_prof: Option<String>,
    ) -> Result<Credentials> {
        let path_spec: bool = opt_path.is_some();

        let path: String;
        let prof: String;

        let res: Result<Credentials>;

        let mut creds: Credentials;

        if path_spec {
            path = opt_path.unwrap();
        } else {
            match Self::get_default_filepath() {
                Ok(p) => path = p,
                Err(e) => return Err(e),
            }
        }

        match opt_prof {
            Some(p) => prof = p,
            None => prof = "default".to_string(),
        }

        creds = Self::from_env();

        res = Self::from_file(&path, &prof);
        if res.is_ok() {
            let mut t_creds = res.unwrap();

            if path_spec {
                std::mem::swap(&mut creds, &mut t_creds);
                creds.merge(t_creds, &[HOST_ID]);
            } else {
                creds.merge(t_creds, &[PAPI_ID, SAPI_ID, SRSA_ID, HOST_ID]);
            }
        } else if path_spec {
            return res;
        }

        for k in [PAPI_ID, SAPI_ID, SRSA_ID] {
            if creds.params.get(&k.to_string()).is_none() {
                return Err(Error::from_str("invalid/incomplete credentials"));
            }
        }

        Ok(Self::create(
            creds.params.remove(&PAPI_ID.to_string()).unwrap(),
            creds.params.remove(&SAPI_ID.to_string()).unwrap(),
            creds.params.remove(&SRSA_ID.to_string()).unwrap(),
            creds.params.remove(&HOST_ID.to_string()),
        ))
    }

    pub fn create(
        papi: String,
        sapi: String,
        srsa: String,
        opt_host: Option<String>,
    ) -> Credentials {
        let mut c = Self::construct();
        let mut host: String;

        match opt_host {
            None => host = SERVER.to_string(),
            Some(h) => host = h,
        }

        if !host.starts_with("http://") && !host.starts_with("https://") {
            host.insert_str(0, "https://");
        }

        c.params.insert(PAPI_ID.to_string(), papi);
        c.params.insert(SAPI_ID.to_string(), sapi);
        c.params.insert(SRSA_ID.to_string(), srsa);
        c.params.insert(HOST_ID.to_string(), host);

        c
    }

    fn merge(&mut self, other: Credentials, which: &[&str]) {
        for w in which {
            let k = w.to_string();
            let sp = other.params.get(&k);

            if self.params.get(&k).is_none() && sp.is_some() {
                self.params.insert(k, sp.unwrap().clone());
            }
        }
    }

    pub(super) fn papi(&self) -> &String {
        return self.params.get(PAPI_ID).unwrap();
    }

    pub(super) fn sapi(&self) -> &String {
        return self.params.get(SAPI_ID).unwrap();
    }

    pub(super) fn srsa(&self) -> &String {
        return self.params.get(SRSA_ID).unwrap();
    }

    pub(super) fn host(&self) -> &String {
        return self.params.get(HOST_ID).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::Credentials;
    use crate::result::Result;

    #[test]
    fn has_default_filepath() -> Result<()> {
        Credentials::get_default_filepath()?;
        Ok(())
    }
}
