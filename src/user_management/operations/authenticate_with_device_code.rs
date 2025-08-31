use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sso::ClientId;
use crate::user_management::{
    AuthenticateError, AuthenticationResponse, DeviceCode, HandleAuthenticateError, IsUnauthorized,
    UserManagement,
};
use crate::{WorkOsError, WorkOsResult};

/// The parameters for [`AuthenticateWithDeviceCode`].
#[derive(Debug, Serialize)]
pub struct AuthenticateWithDeviceCodeParams<'a> {
    /// Identifies the application making the request to the WorkOS server.
    pub client_id: &'a ClientId,

    /// The device code obtained from the device authorization endpoint.
    pub device_code: &'a DeviceCode,
}

#[derive(Serialize)]
struct AuthenticateWithDeviceCodeBody<'a> {
    /// A string constant that distinguishes the method by which your application will receive an access token.
    grant_type: &'a str,

    #[serde(flatten)]
    params: &'a AuthenticateWithDeviceCodeParams<'a>,
}

/// An error returned from [`AuthenticateWithDeviceCode`].
#[derive(Debug, Deserialize, Error)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum AuthenticateWithDeviceCodeError {
    /// The authorization request is still pending as the user hasn’t yet completed the user interaction flow. Continue polling at the specified interval.
    #[error("authorization_pending: {error_description}")]
    AuthorizationPending {
        /// A human-readable message describing the error.
        error_description: String,
    },

    ///The client is polling too frequently and should slow down. Increase your polling interval by at least 5 seconds and continue polling.
    #[error("slow_down: {error_description}")]
    SlowDown {
        /// A human-readable message describing the error.
        error_description: String,
    },

    /// The user declined the authorization request. Stop polling and inform the user that authorization was denied.
    #[error("access_denied: {error_description}")]
    AccessDenied {
        /// A human-readable message describing the error.
        error_description: String,
    },

    /// The device code has expired (typically after 5 minutes). Stop polling and restart the authorization flow if needed.
    #[error("expired_token: {error_description}")]
    ExpiredToken {
        /// A human-readable message describing the error.
        error_description: String,
    },

    /// Other authenticate errors.
    #[error(transparent)]
    #[serde(untagged)]
    Authenticate(AuthenticateError),
}

impl From<AuthenticateWithDeviceCodeError> for WorkOsError<AuthenticateWithDeviceCodeError> {
    fn from(err: AuthenticateWithDeviceCodeError) -> Self {
        Self::Operation(err)
    }
}

impl IsUnauthorized for AuthenticateWithDeviceCodeError {
    fn is_unauthorized(&self) -> bool {
        matches!(self, AuthenticateWithDeviceCodeError::Authenticate(error) if error.is_unauthorized())
    }
}

/// [WorkOS Docs: Authenticate with device code](https://workos.com/docs/reference/authkit/cli-auth/device-code)
#[async_trait]
pub trait AuthenticateWithDeviceCode {
    /// Exchanges a device code for access and refresh tokens as part of the CLI Auth flow.
    ///
    /// This endpoint should be polled repeatedly until the user authorizes the request, declines it, or the device code expires.
    ///
    /// [WorkOS Docs: Authenticate with device code](https://workos.com/docs/reference/authkit/cli-auth/device-code)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::sso::ClientId;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), AuthenticateWithDeviceCodeError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let AuthenticationResponse { user, .. } = workos
    ///     .user_management()
    ///     .authenticate_with_device_code(&AuthenticateWithDeviceCodeParams {
    ///         client_id: &ClientId::from("client_123456789"),
    ///         device_code: &DeviceCode::from("ETaHpDNhfxu0HyLhp6b8HGSh26NzYJSKw3TT6aS7HKKBhTyTD0zAW6ApTTolug0b"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn authenticate_with_device_code(
        &self,
        params: &AuthenticateWithDeviceCodeParams<'_>,
    ) -> WorkOsResult<AuthenticationResponse, AuthenticateWithDeviceCodeError>;
}

#[async_trait]
impl AuthenticateWithDeviceCode for UserManagement<'_> {
    async fn authenticate_with_device_code(
        &self,
        params: &AuthenticateWithDeviceCodeParams<'_>,
    ) -> WorkOsResult<AuthenticationResponse, AuthenticateWithDeviceCodeError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/authenticate")?;

        let body = AuthenticateWithDeviceCodeBody {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            params,
        };

        let authenticate_with_device_code_response = self
            .workos
            .client()
            .post(url)
            .json(&body)
            .send()
            .await?
            .handle_authenticate_error()
            .await?
            .json::<AuthenticationResponse>()
            .await?;

        Ok(authenticate_with_device_code_response)
    }
}

#[cfg(test)]
mod test {
    use matches::assert_matches;
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::sso::AccessToken;
    use crate::user_management::{RefreshToken, UserId};
    use crate::{ApiKey, WorkOs, WorkOsError};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_token_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/authenticate")
            .match_body(Matcher::PartialJson(json!({
                "client_id": "client_123456789",
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": "ETaHpDNhfxu0HyLhp6b8HGSh26NzYJSKw3TT6aS7HKKBhTyTD0zAW6ApTTolug0b",
            })))
            .with_status(200)
            .with_body(
                json!({
                    "user": {
                        "object": "user",
                        "id": "user_01JYHX0DW7077GPTAY8MZVNMQX",
                        "email": "grant.mccode@workos.com",
                        "email_verified": true,
                        "first_name": "Grant",
                        "last_name": "McCode",
                        "profile_picture_url": null,
                        "last_sign_in_at": "2025-06-25T19:16:35.647Z",
                        "created_at": "2025-06-25T01:20:21.355Z",
                        "updated_at": "2025-06-25T19:16:35.647Z",
                        "external_id": null
                    },
                    "organization_id": "org_01JYHNPKWTD5DRGPJHNYBB1HB8",
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkdyYW50IE1jQ29kZSIsImFkbWluIjp0cnVlLCJpYXQiOjEzMzcsInBhc3N3b3JkIjoiaHVudGVyMiJ9.kcmTbx7M89k-3qUXN1UVcy9us6xdPZkDOqQ0UeY3Bws",
                    "refresh_token": "RSzR4ngmJROKFJZQEpp5fNF4y",
                    "authentication_method": "GoogleOAuth"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let response = workos
            .user_management()
            .authenticate_with_device_code(&AuthenticateWithDeviceCodeParams {
                client_id: &ClientId::from("client_123456789"),
                device_code: &DeviceCode::from(
                    "ETaHpDNhfxu0HyLhp6b8HGSh26NzYJSKw3TT6aS7HKKBhTyTD0zAW6ApTTolug0b",
                ),
            })
            .await
            .unwrap();

        assert_eq!(
            response.access_token,
            AccessToken::from(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkdyYW50IE1jQ29kZSIsImFkbWluIjp0cnVlLCJpYXQiOjEzMzcsInBhc3N3b3JkIjoiaHVudGVyMiJ9.kcmTbx7M89k-3qUXN1UVcy9us6xdPZkDOqQ0UeY3Bws"
            )
        );
        assert_eq!(
            response.refresh_token,
            RefreshToken::from("RSzR4ngmJROKFJZQEpp5fNF4y")
        );
        assert_eq!(
            response.user.id,
            UserId::from("user_01JYHX0DW7077GPTAY8MZVNMQX")
        )
    }

    #[tokio::test]
    async fn it_returns_an_unauthorized_error_with_an_invalid_client() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/authenticate")
            .with_status(400)
            .with_body(
                json!({
                    "error": "invalid_client",
                    "error_description": "Invalid client ID."
                })
                .to_string(),
            )
            .create_async()
            .await;

        let result = workos
            .user_management()
            .authenticate_with_device_code(&AuthenticateWithDeviceCodeParams {
                client_id: &ClientId::from("client_123456789"),
                device_code: &DeviceCode::from(
                    "ETaHpDNhfxu0HyLhp6b8HGSh26NzYJSKw3TT6aS7HKKBhTyTD0zAW6ApTTolug0b",
                ),
            })
            .await;

        assert_matches!(result, Err(WorkOsError::Unauthorized))
    }

    #[tokio::test]
    async fn it_returns_an_unauthorized_error_with_an_unauthorized_client() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/authenticate")
            .with_status(400)
            .with_body(
                json!({
                    "error": "unauthorized_client",
                    "error_description": "Unauthorized"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let result = workos
            .user_management()
            .authenticate_with_device_code(&AuthenticateWithDeviceCodeParams {
                client_id: &ClientId::from("client_123456789"),
                device_code: &DeviceCode::from(
                    "ETaHpDNhfxu0HyLhp6b8HGSh26NzYJSKw3TT6aS7HKKBhTyTD0zAW6ApTTolug0b",
                ),
            })
            .await;

        assert_matches!(result, Err(WorkOsError::Unauthorized))
    }

    #[tokio::test]
    async fn it_returns_an_error_when_the_device_code_is_invalid() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/authenticate")
            .with_status(400)
            .with_body(
                json!({
                    "error": "invalid_grant",
                    "error_description": "The code 'ETaHpDNhfxu0HyLhp6b8HGSh26NzYJSKw3TT6aS7HKKBhTyTD0zAW6ApTTolug0b' has expired or is invalid."
                })
                .to_string(),
            )
            .create_async()
            .await;

        let result = workos
            .user_management()
            .authenticate_with_device_code(&AuthenticateWithDeviceCodeParams {
                client_id: &ClientId::from("client_123456789"),
                device_code: &DeviceCode::from(
                    "ETaHpDNhfxu0HyLhp6b8HGSh26NzYJSKw3TT6aS7HKKBhTyTD0zAW6ApTTolug0b",
                ),
            })
            .await;

        if let Err(WorkOsError::Operation(AuthenticateWithDeviceCodeError::Authenticate(
            AuthenticateError::WithError(error),
        ))) = result
        {
            assert_eq!(error.error(), "invalid_grant");
            assert_eq!(
                error.error_description(),
                "The code 'ETaHpDNhfxu0HyLhp6b8HGSh26NzYJSKw3TT6aS7HKKBhTyTD0zAW6ApTTolug0b' has expired or is invalid."
            );
        } else {
            panic!("expected authenticate_with_device_code to return an error")
        }
    }
}
