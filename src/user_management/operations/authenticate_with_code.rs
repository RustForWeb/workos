use std::net::IpAddr;

use async_trait::async_trait;
use serde::Serialize;

use crate::sso::{AuthorizationCode, ClientId};
use crate::user_management::{
    AuthenticateError, AuthenticationResponse, HandleAuthenticateError, UserManagement,
};
use crate::{ApiKey, WorkOsResult};

/// The parameters for [`AuthenticateWithCode`].
#[derive(Debug, Serialize)]
pub struct AuthenticateWithCodeParams<'a> {
    /// Identifies the application making the request to the WorkOS server.
    pub client_id: &'a ClientId,

    /// The randomly generated string used to derive the code challenge that was passed to the authorization url as part of the PKCE flow.
    pub code_verifier: Option<&'a str>,

    /// The authorization value which was passed back as a query parameter in the callback to the redirect URI.
    pub code: &'a AuthorizationCode,

    /// The token of an invitation.
    pub invitation_token: Option<&'a str>,

    /// The IP address of the request from the user who is attempting to authenticate.
    pub ip_address: Option<&'a IpAddr>,

    /// The user agent of the request from the user who is attempting to authenticate.
    pub user_agent: Option<&'a str>,
}

#[derive(Serialize)]
struct AuthenticateWithCodeBody<'a> {
    /// Authenticates the application making the request to the WorkOS server.
    client_secret: &'a ApiKey,

    /// A string constant that distinguishes the method by which your application will receive an access token.
    grant_type: &'a str,

    #[serde(flatten)]
    params: &'a AuthenticateWithCodeParams<'a>,
}

/// [WorkOS Docs: Authenticate with code](https://workos.com/docs/reference/user-management/authentication/code)
#[async_trait]
pub trait AuthenticateWithCode {
    /// Authenticates a user using AuthKit, OAuth or an organization's SSO connection.
    ///
    /// [WorkOS Docs: Authenticate with code](https://workos.com/docs/reference/user-management/authentication/code)
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::{net::IpAddr, str::FromStr};
    ///
    /// # use workos::WorkOsResult;
    /// # use workos::sso::{AuthorizationCode, ClientId};
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), AuthenticateError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let AuthenticationResponse { user, .. } = workos
    ///     .user_management()
    ///     .authenticate_with_code(&AuthenticateWithCodeParams {
    ///         client_id: &ClientId::from("client_123456789"),
    ///         code_verifier: None,
    ///         code: &AuthorizationCode::from("01E2RJ4C05B52KKZ8FSRDAP23J"),
    ///         invitation_token: None,
    ///         ip_address: Some(&IpAddr::from_str("192.0.2.1")?),
    ///         user_agent: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn authenticate_with_code(
        &self,
        params: &AuthenticateWithCodeParams<'_>,
    ) -> WorkOsResult<AuthenticationResponse, AuthenticateError>;
}

#[async_trait]
impl AuthenticateWithCode for UserManagement<'_> {
    async fn authenticate_with_code(
        &self,
        params: &AuthenticateWithCodeParams<'_>,
    ) -> WorkOsResult<AuthenticationResponse, AuthenticateError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/authenticate")?;

        let body = AuthenticateWithCodeBody {
            client_secret: self.workos.key(),
            grant_type: "authorization_code",
            params,
        };

        let authenticate_with_code_response = self
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

        Ok(authenticate_with_code_response)
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
                "grant_type": "authorization_code",
                "code": "abc123",
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
                    "authentication_method": "SSO",
                    "impersonator": {
                        "email": "admin@foocorp.com",
                        "reason": "Investigating an issue with the customer's account."
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let response = workos
            .user_management()
            .authenticate_with_code(&AuthenticateWithCodeParams {
                client_id: &ClientId::from("client_123456789"),
                code_verifier: None,
                code: &AuthorizationCode::from("abc123"),
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
            .authenticate_with_code(&AuthenticateWithCodeParams {
                client_id: &ClientId::from("client_123456789"),
                code_verifier: None,
                code: &AuthorizationCode::from("abc123"),
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
            .authenticate_with_code(&AuthenticateWithCodeParams {
                client_id: &ClientId::from("client_123456789"),
                code_verifier: None,
                code: &AuthorizationCode::from("abc123"),
                invitation_token: None,
                ip_address: None,
                user_agent: None,
            })
            .await;

        assert_matches!(result, Err(WorkOsError::Unauthorized))
    }

    #[tokio::test]
    async fn it_returns_an_error_when_the_authorization_code_is_invalid() {
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
                    "error_description": "The code 'abc123' has expired or is invalid."
                })
                .to_string(),
            )
            .create_async()
            .await;

        let result = workos
            .user_management()
            .authenticate_with_code(&AuthenticateWithCodeParams {
                client_id: &ClientId::from("client_123456789"),
                code_verifier: None,
                code: &AuthorizationCode::from("abc123"),
                invitation_token: None,
                ip_address: None,
                user_agent: None,
            })
            .await;

        if let Err(WorkOsError::Operation(AuthenticateError::WithError(error))) = result {
            assert_eq!(error.error(), "invalid_grant");
            assert_eq!(
                error.error_description(),
                "The code 'abc123' has expired or is invalid."
            );
        } else {
            panic!("expected authenticate_with_code to return an error")
        }
    }
}
