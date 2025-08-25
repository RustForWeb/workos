use std::collections::HashSet;

use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::{Organization, Organizations};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`CreateOrganization`].
#[derive(Debug, Serialize)]
pub struct CreateOrganizationParams<'a> {
    /// The name of the organization.
    pub name: &'a str,

    /// Whether the connections within this organization should allow profiles
    /// that do not have a domain that is present in the set of the organization's
    /// user email domains.
    ///
    /// See [here](https://workos.com/docs/sso/guide/frequently-asked-questions#allow-profiles-outside-organization)
    /// for more details.
    pub allow_profiles_outside_organization: Option<&'a bool>,

    /// The domains of the organization.
    ///
    /// At least one domain is required unless `allow_profiles_outside_organization` is `true`.
    pub domains: HashSet<&'a str>,
}

/// An error returned from [`CreateOrganization`].
#[derive(Debug, Error)]
pub enum CreateOrganizationError {}

impl From<CreateOrganizationError> for WorkOsError<CreateOrganizationError> {
    fn from(err: CreateOrganizationError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Create an Organization](https://workos.com/docs/reference/organization/create)
#[async_trait]
pub trait CreateOrganization {
    /// Creates an [`Organization`].
    ///
    /// [WorkOS Docs: Create an Organization](https://workos.com/docs/reference/organization/create)
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashSet;
    ///
    /// # use workos::WorkOsResult;
    /// # use workos::organizations::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), CreateOrganizationError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization = workos
    ///     .organizations()
    ///     .create_organization(&CreateOrganizationParams {
    ///         name: "Foo Corp",
    ///         allow_profiles_outside_organization: None,
    ///         domains: HashSet::from(["foo-corp.com"]),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_organization(
        &self,
        params: &CreateOrganizationParams<'_>,
    ) -> WorkOsResult<Organization, CreateOrganizationError>;
}

#[async_trait]
impl CreateOrganization for Organizations<'_> {
    async fn create_organization(
        &self,
        params: &CreateOrganizationParams<'_>,
    ) -> WorkOsResult<Organization, CreateOrganizationError> {
        let url = self.workos.base_url().join("/organizations")?;
        let organization = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<Organization>()
            .await?;

        Ok(organization)
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
    async fn it_calls_the_create_organization_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/organizations")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
            .with_body(
                json!({
                    "id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                    "object": "organization",
                    "name": "Foo Corp",
                    "allow_profiles_outside_organization": false,
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z",
                    "domains": [
                        {
                            "object": "organization_domain",
                            "id": "org_domain_01EHZNVPK2QXHMVWCEDQEKY69A",
                            "domain": "foo-corp.com",
                            "organization_id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                            "state": "verified",
                            "verification_strategy": "dns",
                            "verification_token": "m5Oztg3jdK4NJLgs8uIlIprMw",
                            "created_at": "2021-06-25T19:07:33.155Z",
                            "updated_at": "2021-06-25T19:07:33.155Z"
                        }
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization = workos
            .organizations()
            .create_organization(&CreateOrganizationParams {
                name: "Foo Corp",
                allow_profiles_outside_organization: Some(&false),
                domains: HashSet::from(["foo-corp.com"]),
            })
            .await
            .unwrap();

        assert_eq!(
            organization.id,
            OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT")
        )
    }
}
