//! Credentials for authenticating to the Ubiq platform
//!
//! Credentials consist of several unique strings of data and
//! can be found in the .ubiq/credentials file in the user's home
//! directory, in the environment or a combination of both. This
//! module handles retrieval of the credentials from those locations
//! or the creation of credentials from manually-specified strings.
//!
//! # The credentials file
//! The credentials file takes the form:
//! ```pre
//! [profile]
//! ACCESS_KEY_ID = ...
//! SECRET_SIGNING_KEY = ...
//! SECRET_CRYPTO_ACCESS_KEY = ...
//! HOST = ...
//! ```
//! The first three items are required. The last (`HOST`) is not
//! required, and a suitable default will be supplied if it is not
//! present. The host name may or may not contain a leading `http://`
//! or `https://`. By default, this file is located at `.ubiq/credentials`
//! in the user's home directory.
//!
//! `profile` may be specified as `default`, and this profile will
//! be loaded if one is not specified.
//!
//! # Credentials in the environment
//! The credentials may also be specified in the environment using the names
//! above, prefixed with `UBIQ_`, e.g. `ACCESS_KEY_ID` becomes
//! `UBIQ_ACCESS_KEY_ID` in the environment. Rules governing the precedence
//! of these variables is described at [`Credentials::new()`].
//!
//! # Examples
//! ## Default credentials
//! ```rust
//! use ubiq::credentials::Credentials;
//!
//! let creds = Credentials::new(None, None).unwrap();
//! ```
//! ## Manually-specified credentials
//! ```rust
//! use ubiq::credentials::Credentials;
//!
//! let creds = Credentials::create(
//!     "ACCESS_KEY_ID".to_string(),
//!     "SECRET_SIGNING_KEY".to_string(),
//!     "SECRET_CRYPTO_ACCESS_KEY".to_string(),
//!     None,
//! );

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
/// The aggregation of the individual credential components
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

    /// Create a Credentials object from a file, the environment,
    /// or a combination of the two.
    ///
    /// - `opt_path` is a path to the credentials file and may be `None`,
    /// in which case, the file at the "default" location will be used.
    /// - `opt_prof` is the name of the profile to be loaded from the file
    /// and may be `None`, in which case, the "default" profile will be used.
    ///
    /// If the path is not specified, the file at the default location will
    /// be loaded, and variables in the environment (if present) will take
    /// precedence. If the path is specified, the variables from the file
    /// will take precedence, except for the `HOST` variable. The `UBIQ_HOST`
    /// variable in the environment always takes precedence.
    ///
    /// If the host was not specified at all, a suitable default will be
    /// provided. Upon successful return, all credential components will
    /// be present.
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

    /// Create credentials from manually-specified components
    ///
    /// - `papi` corresponds to the `ACCESS_KEY_ID`
    /// - `sapi` corresponds to the `SECRET_SIGNING_KEY`
    /// - `srsa` corresponds to the `SECRET_CRYPTO_ACCES_KEY`
    /// - `opt_host` is the host name of the API server and may be `None`.
    /// As before, the host may or may not contain the HTTP scheme.
    ///
    /// The function populates the components of the credentials as specified
    /// except for the host which will have the scheme added if it is missing.
    /// As such, the function always succeeds.
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

    pub(crate) fn papi(&self) -> &String {
        return self.params.get(PAPI_ID).unwrap();
    }

    pub(crate) fn sapi(&self) -> &String {
        return self.params.get(SAPI_ID).unwrap();
    }

    pub(crate) fn srsa(&self) -> &String {
        return self.params.get(SRSA_ID).unwrap();
    }

    pub(crate) fn host(&self) -> &String {
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
