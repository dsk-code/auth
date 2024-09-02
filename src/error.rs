use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Initial key set failed")]
    InvalidKeyset,
    #[error("JWT validation failed: {0}")]
    DecodeInvalidJwt(#[from] jsonwebtoken::errors::Error),
    #[error("not found {0}")]
    NotFound(String),
}

