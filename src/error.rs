#[derive(Debug)]
pub struct Error {
    why: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(f, "{}", self.why);
    }
}

impl Error {
    pub fn from_string(why: String) -> Error {
        return Error { why: why };
    }

    pub fn from_str(why: &str) -> Error {
        return Error {
            why: why.to_string(),
        };
    }
}
