use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::organizations::OrganizationId;
use crate::user_management::UserId;
use crate::widgets::Widgets;
use crate::{ResponseExt, WorkOsResult};

/// The scope of a widget token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WidgetTokenScope {
    /// Manage users.
    #[serde(rename = "widgets:users-table:manage")]
    ManageUsers,

    /// Manage SSO.
    #[serde(rename = "widgets:sso:manage")]
    ManageSso,

    /// Manage domain verification.
    #[serde(rename = "widgets:domain-verification:manage")]
    ManageDomainVerification,
}

/// The parameters for [`GenerateToken`].
#[derive(Debug, Serialize)]
pub struct GenerateTokenParams<'a> {
    /// An Organization identifier.
    pub organization_id: &'a OrganizationId,

    /// A User identifier.
    pub user_id: Option<&'a UserId>,

    /// Scopes to include in the widget token.
    pub scopes: Option<Vec<WidgetTokenScope>>,
}

/// The response for [`GenerateToken`].
#[derive(Debug, Deserialize)]
pub struct GenerateTokenResponse {
    /// An ephemeral token to access WorkOS widgets.
    pub token: String,
}

/// An error returned from [`GenerateToken`].
#[derive(Debug)]
pub enum GenerateTokenError {}

/// [WorkOS Docs: Generate a Widget token](https://workos.com/docs/reference/widgets/get-token)
#[async_trait]
pub trait GenerateToken {
    /// Generate a widget token scoped to an organization and user with the specified scopes.
    ///
    /// [WorkOS Docs: Generate a Widget token](https://workos.com/docs/reference/widgets/get-token)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organizations::OrganizationId;
    /// # use workos::user_management::UserId;
    /// # use workos::widgets::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GenerateTokenError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let GenerateTokenResponse { token } = workos
    ///     .widgets()
    ///     .generate_token(&GenerateTokenParams {
    ///         organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
    ///         user_id: Some(&UserId::from("usr_01EHZNVPK3SFK441A1RGBFSHRT")),
    ///         scopes: Some(vec![WidgetTokenScope::ManageUsers]),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn generate_token(
        &self,
        params: &GenerateTokenParams<'_>,
    ) -> WorkOsResult<GenerateTokenResponse, GenerateTokenError>;
}

#[async_trait]
impl GenerateToken for Widgets<'_> {
    async fn generate_token(
        &self,
        params: &GenerateTokenParams<'_>,
    ) -> WorkOsResult<GenerateTokenResponse, GenerateTokenError> {
        let url = self.workos.base_url().join("/widgets/token")?;

        let response = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<GenerateTokenResponse>()
            .await?;

        Ok(response)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::organizations::OrganizationId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_generate_token_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&dbg!(server.url()))
            .unwrap()
            .build();

        server
            .mock("POST", "/widgets/token")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body(Matcher::Json(json!({
                "organization_id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                "user_id": "usr_01EHZNVPK3SFK441A1RGBFSHRT",
                "scopes": ["widgets:users-table:manage"]
            })))
            .with_status(201)
            .with_body(
                json!({
                    "token": "token"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let GenerateTokenResponse { token } = workos
            .widgets()
            .generate_token(&GenerateTokenParams {
                organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
                user_id: Some(&UserId::from("usr_01EHZNVPK3SFK441A1RGBFSHRT")),
                scopes: Some(vec![WidgetTokenScope::ManageUsers]),
            })
            .await
            .unwrap();

        assert_eq!(token, "token".to_string())
    }
}
