use serde::{Deserialize, Serialize};

use crate::{
    organizations::OrganizationId,
    sso::AccessToken,
    user_management::{CookieSession, SealDataError, SessionCookieData},
};

use super::{Impersonator, RefreshToken, User};

/// The authentication method used to initiate the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum AuthenticationMethod {
    /// Single Sign-On (SSO)
    SSO,

    /// Password.
    Password,

    /// Passkey.
    Passkey,

    /// Apple OAuth.
    AppleOAuth,

    /// GitHub OAuth.
    GitHubOAuth,

    /// Google OAuth.
    GoogleOAuth,

    /// Microsoft OAuth.
    MicrosoftOAuth,

    /// Magic auth.
    MagicAuth,

    /// Impersenation.
    Impersonation,
}

/// The response for authenticate requests.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct AuthenticationResponse {
    /// The corresponding user object.
    pub user: User,

    /// The organization the user selected to sign in to.
    pub organization_id: Option<OrganizationId>,

    /// A JWT containing information about the session.
    pub access_token: AccessToken,

    /// Exchange this token for a new access token.
    pub refresh_token: RefreshToken,

    /// The authentication method used to initiate the session.
    pub authentication_method: AuthenticationMethod,

    /// The WorkOS Dashboard user who is impersonating the user.
    pub impersonator: Option<Impersonator>,
}

impl AuthenticationResponse {
    /// The sealed session data.
    pub fn sealed_session(&self, cookie_password: &str) -> Result<String, SealDataError> {
        CookieSession::seal_data(
            SessionCookieData {
                user: self.user.clone(),
                organization_id: self.organization_id.clone(),
                access_token: self.access_token.clone(),
                refresh_token: self.refresh_token.clone(),
                impersonator: self.impersonator.clone(),
            },
            cookie_password,
        )
    }
}
