use serde::{Deserialize, Serialize};

use crate::{
    organizations::OrganizationId,
    sso::AccessToken,
    user_management::{Impersonator, RefreshToken, User},
};

/// The claims in an access token.
#[derive(Debug, Deserialize)]
pub struct AccessTokenClaims {
    /// The ID of the session.
    pub sid: String,

    /// The organization the user selected to sign in to.
    pub org_id: Option<String>,

    /// The role of the user.
    pub role: Option<String>,

    /// A list of permissions.
    pub permissions: Option<Vec<String>>,

    /// A list of entitlements.
    pub entitlements: Option<Vec<String>>,

    /// A list of feature flags.
    pub feature_flags: Option<Vec<String>>,
}

/// The data in a session cookie.
#[derive(Debug, Serialize, Deserialize)]
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
