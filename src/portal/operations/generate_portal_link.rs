use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::organizations::OrganizationId;
use crate::portal::{GeneratePortalLinkIntent, Portal};
use crate::{ResponseExt, WorkOsResult};

/// The parameters for [`GeneratePortalLink`].
#[derive(Debug, Serialize)]
pub struct GeneratePortalLinkParams<'a> {
    /// The ID of the organization.
    #[serde(rename = "organization")]
    pub organization_id: &'a OrganizationId,

    /// The intent of the Admin Portal.
    pub intent: GeneratePortalLinkIntent,

    /// The URL to go to when an admin clicks on your logo in the Admin Portal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<&'a str>,

    /// The URL to redirect the admin to when they finish setup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_url: Option<&'a str>,
}

/// The response for [`GeneratePortalLink`].
#[derive(Debug, Deserialize)]
pub struct GeneratePortalLinkResponse {
    /// An ephemeral link to initiate the Admin Portal.
    pub link: String,
}

/// An error returned from [`GeneratePortalLink`].
#[derive(Debug)]
pub enum GeneratePortalLinkError {}

/// [WorkOS Docs: Generate a Portal Link](https://workos.com/docs/reference/admin-portal/portal-link/generate)
#[async_trait]
pub trait GeneratePortalLink {
    /// Generate a Portal Link scoped to an Organization.
    ///
    /// [WorkOS Docs: Generate a Portal Link](https://workos.com/docs/reference/admin-portal/portal-link/generate)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organizations::OrganizationId;
    /// # use workos::portal::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GeneratePortalLinkError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let GeneratePortalLinkResponse { link } = workos
    ///     .portal()
    ///     .generate_portal_link(&GeneratePortalLinkParams {
    ///         organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
    ///         intent: GeneratePortalLinkIntent::Sso,
    ///         return_url: None,
    ///         success_url: None,
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn generate_portal_link(
        &self,
        params: &GeneratePortalLinkParams<'_>,
    ) -> WorkOsResult<GeneratePortalLinkResponse, GeneratePortalLinkError>;
}

#[async_trait]
impl GeneratePortalLink for Portal<'_> {
    async fn generate_portal_link(
        &self,
        params: &GeneratePortalLinkParams<'_>,
    ) -> WorkOsResult<GeneratePortalLinkResponse, GeneratePortalLinkError> {
        let url = self.workos.base_url().join("/portal/generate_link")?;
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
            .json::<GeneratePortalLinkResponse>()
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
    async fn it_calls_the_generate_portal_link_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&dbg!(server.url()))
            .unwrap()
            .build();

        server
            .mock("POST", "/portal/generate_link")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body(Matcher::Json(json!({
                "organization": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                "intent": "sso",
            })))
            .with_status(201)
            .with_body(
                json!({
                    "link": "https://setup.workos.com?token=token"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let GeneratePortalLinkResponse { link } = workos
            .portal()
            .generate_portal_link(&GeneratePortalLinkParams {
                organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
                intent: GeneratePortalLinkIntent::Sso,
                return_url: None,
                success_url: None,
            })
            .await
            .unwrap();

        assert_eq!(link, "https://setup.workos.com?token=token".to_string())
    }
}
