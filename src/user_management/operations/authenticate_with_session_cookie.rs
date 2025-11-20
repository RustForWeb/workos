use async_trait::async_trait;
use serde::Serialize;

use crate::user_management::{
    AuthenticateWithSessionCookieError, AuthenticateWithSessionCookieResponse, UserManagement,
};

/// The parameters for [`AuthenticateWithSessionCookie`].
#[derive(Debug, Serialize)]
pub struct AuthenticateWithSessionCookieOptions<'a> {
    /// WorkOS session cookie value from the user's browser.
    pub session_data: &'a str,

    /// Password used to unseal the session cookie.
    ///
    /// Must be the same as the password used to seal the cookie.
    pub cookie_password: &'a str,
}

/// [WorkOS Docs: Authenticate with session cookie](https://workos.com/docs/reference/user-management/authentication/session-cookie)
#[async_trait]
pub trait AuthenticateWithSessionCookie {
    /// Authenticates a user using an AuthKit session cookie.
    ///
    /// [WorkOS Docs: Authenticate with session cookie](https://workos.com/docs/reference/user-management/authentication/session-cookie)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> Result<(), AuthenticateWithSessionCookieError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let AuthenticateWithSessionCookieResponse { user, .. } = workos
    ///     .user_management()
    ///     .authenticate_with_session_cookie(&AuthenticateWithSessionCookieOptions {
    ///         session_data: "sealed_session_cookie_data",
    ///         cookie_password: "password_previously_used_to_seal_session_cookie",
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn authenticate_with_session_cookie(
        &self,
        options: &AuthenticateWithSessionCookieOptions<'_>,
    ) -> Result<AuthenticateWithSessionCookieResponse, AuthenticateWithSessionCookieError>;
}

#[async_trait]
impl AuthenticateWithSessionCookie for UserManagement<'_> {
    async fn authenticate_with_session_cookie(
        &self,
        options: &AuthenticateWithSessionCookieOptions<'_>,
    ) -> Result<AuthenticateWithSessionCookieResponse, AuthenticateWithSessionCookieError> {
        let session = self.load_sealed_session(options.session_data, options.cookie_password);

        session.authenticate().await
    }
}
