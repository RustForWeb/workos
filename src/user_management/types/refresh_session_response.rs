use thiserror::Error;

use crate::{
    WorkOsError,
    user_management::{AuthenticateError, AuthenticationResponse, SealDataError, UnsealDataError},
};

/// Refresh session error.
#[derive(Debug, Error)]
pub enum RefreshSessionError {
    /// Invalid session cookie.
    #[error("invalid session cookie: {0}")]
    InvalidSessionCookie(#[from] UnsealDataError),

    /// Missing client ID.
    #[error("missing client ID")]
    MissingClientId,

    /// Authenticate error.
    #[error(transparent)]
    Authenticate(#[from] WorkOsError<AuthenticateError>),

    /// Seal data error.
    #[error(transparent)]
    SealData(#[from] SealDataError),
}

/// Refresh session response.
#[derive(Debug, PartialEq, Eq)]
pub struct RefreshSessionResponse {
    /// The sealed session.
    pub sealed_session: String,

    /// The session.
    pub session: AuthenticationResponse,
}
