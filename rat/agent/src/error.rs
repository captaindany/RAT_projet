use std::fmt;

#[derive(Debug)]
pub enum Error {
    Internal(String),
    Api(String),
    Io(std::io::Error),
    Ssh(ssh2::Error),
    Zip(zip::result::ZipError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Internal(msg) => write!(f, "Internal error: {}", msg),
            Error::Api(msg) => write!(f, "API error: {}", msg),
            Error::Io(err) => write!(f, "IO error: {}", err),
            Error::Ssh(err) => write!(f, "SSH error: {}", err),
            Error::Zip(err) => write!(f, "Zip error: {}", err),
        }
    }
}

impl std::error::Error for Error {}

// ── Standard conversions ──────────────────────────────────────────────────────

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::Internal(err.to_string())
    }
}

impl From<ssh2::Error> for Error {
    fn from(err: ssh2::Error) -> Self {
        Error::Ssh(err)
    }
}

impl From<zip::result::ZipError> for Error {
    fn from(err: zip::result::ZipError) -> Self {
        Error::Zip(err)
    }
}

// ── Crypto conversions (needed by run.rs and register.rs) ─────────────────────

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(err: chacha20poly1305::aead::Error) -> Self {
        Error::Internal(format!("Cipher error: {}", err))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Internal(format!("JSON error: {}", err))
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Error::Internal(format!("Signature error: {}", err))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Internal(format!("Base64 decode error: {}", err))
    }
}
