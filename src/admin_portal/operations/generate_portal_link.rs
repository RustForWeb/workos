use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::admin_portal::AdminPortal;
use crate::organizations::OrganizationId;
use crate::{ResponseExt, WorkOsResult};

/// The intent of an Admin Portal session.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminPortalIntent {
    /// The Admin Portal will be used to setup Single Sign-On (SSO).
    Sso,

    /// The Admin Portal wil be used to setup Directory Sync.
    #[serde(rename = "dsync")]
    DirectorySync,
}

/// The target of the Admin Portal.
#[derive(Debug, Serialize)]
#[serde(untagged, rename_all = "snake_case")]
pub enum AdminPortalTarget {
    /// The Admin Portal session should target an organization.
    Organization {
        /// The ID of the organization.
        #[serde(rename = "organization")]
        organization_id: OrganizationId,

        /// The intent of the Admin Portal session.
        intent: AdminPortalIntent,
    },
}

/// The parameters for [`GeneratePortalLink`].
#[derive(Debug, Serialize)]
pub struct GeneratePortalLinkParams<'a> {
    /// The target of the Admin Portal.
    #[serde(flatten)]
    pub target: &'a AdminPortalTarget,

    /// The URL to which the Admin Portal should send users when they click on the link
    /// to return to your application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
}

/// The response for [`GeneratePortalLink`].
#[derive(Debug, Deserialize)]
pub struct GeneratePortalLinkResponse {
    /// The generate Admin Portal link.
    pub link: String,
}

/// An error returned from [`GeneratePortalLink`].
#[derive(Debug)]
pub enum GeneratePortalLinkError {}

/// [WorkOS Docs: Generate a Portal Link](https://workos.com/docs/reference/admin-portal/portal-link/generate)
#[async_trait]
pub trait GeneratePortalLink {
    /// Generates an Admin Portal link.
    ///
    /// [WorkOS Docs: Generate a Portal Link](https://workos.com/docs/reference/admin-portal/portal-link/generate)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::admin_portal::*;
    /// # use workos::organizations::OrganizationId;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GeneratePortalLinkError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let GeneratePortalLinkResponse { link } = workos
    ///     .admin_portal()
    ///     .generate_portal_link(&GeneratePortalLinkParams {
    ///         target: &AdminPortalTarget::Organization {
    ///             organization_id: OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
    ///             intent: AdminPortalIntent::Sso,
    ///         },
    ///         return_url: None,
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
impl GeneratePortalLink for AdminPortal<'_> {
    async fn generate_portal_link(
        &self,
        params: &GeneratePortalLinkParams<'_>,
    ) -> WorkOsResult<GeneratePortalLinkResponse, GeneratePortalLinkError> {
        let url = self.workos.base_url().join("/portal/generate_link")?;
        let generate_link_response = self
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

        Ok(generate_link_response)
    }
}

#[cfg(test)]
mod test {
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

        server.mock("POST", "/portal/generate_link")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body(r#"{"organization":"org_01EHZNVPK3SFK441A1RGBFSHRT","intent":"sso"}"#)
            .with_status(201)
            .with_body(
                json!({
                    "link": "https://setup.workos.com/portal/launch?secret=JteZqfJZqUcgWGaYCC6iI0gW0"
                })
                .to_string(),
            )
            .create_async().await;

        let GeneratePortalLinkResponse { link } = workos
            .admin_portal()
            .generate_portal_link(&GeneratePortalLinkParams {
                target: &AdminPortalTarget::Organization {
                    organization_id: OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
                    intent: AdminPortalIntent::Sso,
                },
                return_url: None,
            })
            .await
            .unwrap();

        assert_eq!(
            link,
            "https://setup.workos.com/portal/launch?secret=JteZqfJZqUcgWGaYCC6iI0gW0".to_string()
        )
    }
}
