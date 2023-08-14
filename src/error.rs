#[derive(Debug)]
pub struct Error {
    why: String,
}

impl Error {
    pub fn new(why: &String) -> Error {
        return Error {
            why: why.clone()
        };
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        return write!(f, "{}", self.why);
    }
}
