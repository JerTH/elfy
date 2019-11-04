use std::error::Error;
use std::fmt::{ Display, Formatter };

#[derive(Debug)]
pub enum ParseElfError {
    IoError{ inner: std::io::Error },
    InvalidDataClass,
    InvalidSectionType{ section_type: u32 },
}

impl Error for ParseElfError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ParseElfError::IoError{ inner } => Some(inner),
            _ => None,
        }
    }
}

impl Display for ParseElfError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<std::io::Error> for ParseElfError {
    fn from(err: std::io::Error) -> ParseElfError {
        ParseElfError::IoError{ inner: err }
    }
}
