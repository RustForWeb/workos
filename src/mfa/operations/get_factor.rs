use async_trait::async_trait;
use thiserror::Error;

use crate::mfa::{AuthenticationFactor, AuthenticationFactorId, Mfa};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetFactor`].
#[derive(Debug, Error)]
pub enum GetFactorError {}

impl From<GetFactorError> for WorkOsError<GetFactorError> {
    fn from(err: GetFactorError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get Factor](https://workos.com/docs/reference/mfa/get-factor)
#[async_trait]
pub trait GetFactor {
    /// Gets an Authentication Factor.
    ///
    /// [WorkOS Docs: Get Factor](https://workos.com/docs/reference/mfa/get-factor)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::mfa::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetFactorError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let factor = workos
    ///     .mfa()
    ///     .get_factor(&AuthenticationFactorId::from("auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_factor(
        &self,
        id: &AuthenticationFactorId,
    ) -> WorkOsResult<AuthenticationFactor, GetFactorError>;
}

#[async_trait]
impl GetFactor for Mfa<'_> {
    async fn get_factor(
        &self,
        id: &AuthenticationFactorId,
    ) -> WorkOsResult<AuthenticationFactor, GetFactorError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/auth/factors/{id}"))?;

        let organization = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<AuthenticationFactor>()
            .await?;

        Ok(organization)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_factor_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/auth/factors/auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                "object": "authentication_factor",
                "id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
                "created_at": "2022-02-15T15:14:19.392Z",
                "updated_at": "2022-02-15T15:14:19.392Z",
                "type": "totp",
                "totp": {
                    "issuer": "Foo Corp",
                    "user": "alan.turing@foo-corp.com",
                    "qr_code": "data:image/png;base64,{base64EncodedPng}",
                    "secret": "NAGCCFS3EYRB422HNAKAKY3XDUORMSRF",
                    "uri": "otpauth://totp/FooCorp:alan.turing@example.com?secret=NAGCCFS3EYRB422HNAKAKY3XDUORMSRF&issuer=FooCorp"
                }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let factor = workos
            .mfa()
            .get_factor(&AuthenticationFactorId::from(
                "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
            ))
            .await
            .unwrap();

        assert_eq!(
            factor.id,
            AuthenticationFactorId::from("auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ")
        )
    }
}
