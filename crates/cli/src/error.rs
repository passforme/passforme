use std::fmt;
use std::io;
use std::path::PathBuf;

use passforme_core::generator::GeneratorError;
use passforme_core::kit::KitError;
use passforme_core::vault::VaultError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(PathBuf, io::Error),
    Vault(VaultError),
    Generator(GeneratorError),
    Kit(KitError),
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "{}: {e}", path.display()),
            Self::Vault(e) => e.fmt(f),
            Self::Generator(e) => e.fmt(f),
            Self::Kit(e) => write!(f, "Secret Key file: {e}"),
            Self::Message(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

impl From<VaultError> for Error {
    fn from(e: VaultError) -> Self {
        Self::Vault(e)
    }
}

impl From<passforme_core::kdf::KdfError> for Error {
    fn from(e: passforme_core::kdf::KdfError) -> Self {
        Self::Vault(VaultError::Kdf(e))
    }
}

impl From<GeneratorError> for Error {
    fn from(e: GeneratorError) -> Self {
        Self::Generator(e)
    }
}

impl From<KitError> for Error {
    fn from(e: KitError) -> Self {
        Self::Kit(e)
    }
}

impl From<String> for Error {
    fn from(m: String) -> Self {
        Self::Message(m)
    }
}

impl From<&str> for Error {
    fn from(m: &str) -> Self {
        Self::Message(m.to_owned())
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(PathBuf::from("<terminal>"), e)
    }
}
