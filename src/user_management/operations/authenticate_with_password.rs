use std::net::IpAddr;

use async_trait::async_trait;
use serde::Serialize;

use crate::sso::ClientId;
use crate::user_management::{
    AuthenticateError, AuthenticationResponse, HandleAuthenticateError, UserManagement,
};
use crate::{ApiKey, WorkOsResult};

/// The parameters for [`AuthenticateWithPassword`].
#[derive(Debug, Serialize)]
pub struct AuthenticateWithPasswordParams<'a> {
    /// Identifies the application making the request to the WorkOS server.
    pub client_id: &'a ClientId,

    /// The email address of the user.
    pub email: &'a str,

    /// The password of the user.
    pub password: &'a str,

    /// The token of an invitation.
    pub invitation_token: Option<&'a str>,

    /// The IP address of the request from the user who is attempting to authenticate.
    pub ip_address: Option<&'a IpAddr>,

    /// The user agent of the request from the user who is attempting to authenticate.
    pub user_agent: Option<&'a str>,
}

#[derive(Serialize)]
struct AuthenticateWithPasswordBody<'a> {
    client_secret: &'a ApiKey,
    grant_type: &'a str,

    #[serde(flatten)]
    params: &'a AuthenticateWithPasswordParams<'a>,
}

/// [WorkOS Docs: Authenticate with password](https://workos.com/docs/reference/user-management/authentication/password)
#[async_trait]
pub trait AuthenticateWithPassword {
    /// Authenticates a user with email and password.
    ///
    /// [WorkOS Docs: Authenticate with password](https://workos.com/docs/reference/user-management/authentication/password)
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{net::IpAddr, str::FromStr};
    ///
    /// # use workos_sdk::WorkOsResult;
    /// # use workos_sdk::sso::ClientId;
    /// # use workos_sdk::user_management::*;
    /// use workos_sdk::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), AuthenticateError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let AuthenticationResponse { user, .. } = workos
    ///     .user_management()
    ///     .authenticate_with_password(&AuthenticateWithPasswordParams {
    ///         client_id: &ClientId::from("client_123456789"),
    ///         email: "marcelina@example.com",
    ///         password: "i8uv6g34kd490s",
    ///         invitation_token: None,
    ///         ip_address: Some(&IpAddr::from_str("192.0.2.1")?),
    ///         user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn authenticate_with_password(
        &self,
        params: &AuthenticateWithPasswordParams<'_>,
    ) -> WorkOsResult<AuthenticationResponse, AuthenticateError>;
}

#[async_trait]
impl AuthenticateWithPassword for UserManagement<'_> {
    async fn authenticate_with_password(
        &self,
        params: &AuthenticateWithPasswordParams<'_>,
    ) -> WorkOsResult<AuthenticationResponse, AuthenticateError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/authenticate")?;

        let body = AuthenticateWithPasswordBody {
            client_secret: self.workos.key(),
            grant_type: "password",
            params,
        };

        let authenticate_with_password_response = self
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

        Ok(authenticate_with_password_response)
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
                "client_secret": "sk_example_123456789",
                "grant_type": "password",
                "email": "marcelina@example.com",
                "password": "i8uv6g34kd490s",
            })))
            .with_status(200)
            .with_body(
                json!({
                    "user": {
                        "object": "user",
                        "id": "user_01E4ZCR3C56J083X43JQXF3JK5",
                        "email": "marcelina.davis@example.com",
                        "first_name": "Marcelina",
                        "last_name": "Davis",
                        "email_verified": true,
                        "profile_picture_url": "https://workoscdn.com/images/v1/123abc",
                        "metadata": {},
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    },
                    "organization_id": "org_01H945H0YD4F97JN9MATX7BYAG",
                    "access_token": "eyJhb.nNzb19vaWRjX2tleV9.lc5Uk4yWVk5In0",
                    "refresh_token": "yAjhKk123NLIjdrBdGZPf8pLIDvK",
                    "authentication_method": "Password",
                })
                .to_string(),
            )
            .create_async()
            .await;

        let response = workos
            .user_management()
            .authenticate_with_password(&AuthenticateWithPasswordParams {
                client_id: &ClientId::from("client_123456789"),
                email: "marcelina@example.com",
                password: "i8uv6g34kd490s",
                invitation_token: None,
                ip_address: None,
                user_agent: None,
            })
            .await
            .unwrap();

        assert_eq!(
            response.access_token,
            AccessToken::from("eyJhb.nNzb19vaWRjX2tleV9.lc5Uk4yWVk5In0")
        );
        assert_eq!(
            response.refresh_token,
            RefreshToken::from("yAjhKk123NLIjdrBdGZPf8pLIDvK")
        );
        assert_eq!(
            response.user.id,
            UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5")
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
            .authenticate_with_password(&AuthenticateWithPasswordParams {
                client_id: &ClientId::from("client_123456789"),
                email: "marcelina@example.com",
                password: "i8uv6g34kd490s",
                invitation_token: None,
                ip_address: None,
                user_agent: None,
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
            .authenticate_with_password(&AuthenticateWithPasswordParams {
                client_id: &ClientId::from("client_123456789"),
                email: "marcelina@example.com",
                password: "i8uv6g34kd490s",
                invitation_token: None,
                ip_address: None,
                user_agent: None,
            })
            .await;

        assert_matches!(result, Err(WorkOsError::Unauthorized))
    }
}
