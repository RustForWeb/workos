use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use thiserror::Error;

use crate::sso::ClientId;
use crate::user_management::UserManagement;
use crate::{ResponseExt, WorkOsResult};

use super::GetJwksUrl;

/// An error returned from [`GetJwks`].
#[derive(Debug, Error)]
pub enum GetJwksError {}

/// [WorkOS Docs: Get JWKS](https://workos.com/docs/reference/user-management/session-tokens/jwks)
#[async_trait]
pub trait GetJwks {
    /// Get JSON Web Key Set (JWKS).
    ///
    /// [WorkOS Docs: Get JWKS](https://workos.com/docs/reference/user-management/session-tokens/jwks)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::sso::ClientId;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetJwksError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let jwks = workos
    ///     .user_management()
    ///     .get_jwks(&ClientId::from("client_123456789"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_jwks(&self, client_id: &ClientId) -> WorkOsResult<JwkSet, GetJwksError>;
}

#[async_trait]
impl GetJwks for UserManagement<'_> {
    async fn get_jwks(&self, client_id: &ClientId) -> WorkOsResult<JwkSet, GetJwksError> {
        let url = self.get_jwks_url(client_id)?;

        let jwks = self
            .workos
            .client()
            .get(url)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<JwkSet>()
            .await?;

        Ok(jwks)
    }
}

#[cfg(test)]
mod test {
    use matches::assert_matches;
    use reqwest::StatusCode;
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, JsonOrText, WorkOs, WorkOsError};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_jwks_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/sso/jwks/client_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "keys": []
                })
                .to_string(),
            )
            .create_async()
            .await;

        let jwks = workos
            .user_management()
            .get_jwks(&ClientId::from("client_123456789"))
            .await
            .unwrap();

        assert_eq!(jwks, JwkSet { keys: vec![] })
    }

    #[tokio::test]
    async fn it_returns_an_error_when_the_get_jwks_endpoint_returns_not_found() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/sso/jwks/client_123456789")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "message": "Not Found"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let result = workos
            .user_management()
            .get_jwks(&ClientId::from("client_123456789"))
            .await;

        assert_matches!(
            result,
            Err(WorkOsError::Unknown {
                status: StatusCode::NOT_FOUND,
                body: JsonOrText::Json(json)
            }) if json == json!({
                "message": "Not Found"
            })
        )
    }
}
