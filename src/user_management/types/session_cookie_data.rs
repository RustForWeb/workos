use derive_more::Display;
use serde::Deserialize;

use crate::{
    organizations::OrganizationId,
    roles::RoleSlug,
    sso::AccessToken,
    user_management::{Impersonator, RefreshToken, SessionId, User},
};

/// The claims in an access token.
#[derive(Debug, Deserialize)]
pub struct AccessTokenClaims {
    pub sid: String,
    pub org_id: Option<String>,
    pub role: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub entitlements: Option<Vec<String>>,
    pub feature_flags: Option<Vec<String>>,
}

/// The data in a session cookie.
#[derive(Debug, Deserialize)]
pub struct SessionCookieData {
    /// The corresponding user object.
    pub user: User,

    /// The organization the user selected to sign in to.
    pub organization_id: Option<OrganizationId>,

    /// A JWT containing information about the session.
    pub access_token: AccessToken,

    /// Exchange this token for a new access token.
    pub refresh_token: RefreshToken,

    /// The WorkOS Dashboard user who is impersonating the user.
    pub impersonator: Option<Impersonator>,
}

/// TODO
#[derive(Clone, Copy, Debug, Display, PartialEq, Eq)]
pub enum AuthenticatieWithSessionCookieFailureReason {
    /// Invalid JWT.
    #[display("invalid_jwt")]
    InvalidJwt,

    /// Invalid session cookie.
    #[display("invalid_session_cookie")]
    InvalidSessionCookie,
}

/// TODO
#[derive(Debug)]
pub enum AuthenticatieWithSessionCookieResponse {
    /// TODO
    Failure(AuthenticatieWithSessionCookieFailureResponse),

    /// TODO
    Success(Box<AuthenticatieWithSessionCookieSuccessResponse>),
}

/// TODO
#[derive(Debug)]
pub struct AuthenticatieWithSessionCookieFailureResponse {
    pub reason: AuthenticatieWithSessionCookieFailureReason,
}

/// TODO
#[derive(Debug)]
pub struct AuthenticatieWithSessionCookieSuccessResponse {
    pub session_id: SessionId,
    pub organization_id: Option<OrganizationId>,
    pub role: Option<RoleSlug>,
    pub permissions: Option<Vec<String>>,
    pub entitlements: Option<Vec<String>>,
    pub feature_flags: Option<Vec<String>>,
    pub user: User,
    pub impersonator: Option<Impersonator>,
    pub access_token: AccessToken,
}
