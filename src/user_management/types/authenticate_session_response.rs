use thiserror::Error;

use crate::{
    FindJwkError, WorkOsError,
    organizations::OrganizationId,
    roles::RoleSlug,
    sso::AccessToken,
    user_management::{Impersonator, JwksError, SessionId, UnsealDataError, User},
};

/// Authenticate with session cookie error.
#[derive(Debug, Error)]
pub enum AuthenticateWithSessionCookieError {
    /// Invalid session cookie.
    #[error("invalid session cookie: {0}")]
    InvalidSessionCookie(#[from] UnsealDataError),

    /// Invalid JWT.
    #[error("invalid JWT: {0}")]
    InvalidJwt(#[from] jsonwebtoken::errors::Error),

    /// Missing JWK ID.
    #[error("missing JWK ID")]
    MissingJwkId,

    /// JWKS error.
    #[error(transparent)]
    Jwks(#[from] JwksError),

    /// Find JWK error.
    #[error(transparent)]
    FindJwk(#[from] WorkOsError<FindJwkError>),

    /// JWK not found in JWKS.
    #[error("JWK not found in JWKS")]
    JwkNotFound,
}

/// Authenticate with session cookie response.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticateWithSessionCookieResponse {
    /// The ID of the session.
    pub session_id: SessionId,

    /// The organization the user selected to sign in to.
    pub organization_id: Option<OrganizationId>,

    /// The role of the user.
    pub role: Option<RoleSlug>,

    /// A list of permission slugs.
    pub permissions: Option<Vec<String>>,

    /// A list of entitlements.
    pub entitlements: Option<Vec<String>>,

    /// A list of feature flags.
    pub feature_flags: Option<Vec<String>>,

    /// The user.
    pub user: User,

    /// The WorkOS Dashboard user who is impersonating the user.
    pub impersonator: Option<Impersonator>,

    /// A JWT containing information about the session.
    pub access_token: AccessToken,
}
