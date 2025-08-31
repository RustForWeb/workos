use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::{DomainData, Organization, Organizations};
use crate::{Metadata, ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`CreateOrganization`].
#[derive(Debug, Serialize)]
pub struct CreateOrganizationParams<'a> {
    /// A descriptive name for the Organization.
    ///
    /// This field does not need to be unique.
    pub name: &'a str,

    /// The domains of the organization.
    pub domain_data: Vec<DomainData<'a>>,

    /// The external ID of the Organization.
    pub external_id: Option<&'a str>,

    /// Object containing metadata key/value pairs associated with the Organization.
    pub metadata: Option<Metadata>,
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
    /// Creates a new organization in the current environment.
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
    /// use workos::{ApiKey, Metadata, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), CreateOrganizationError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization = workos
    ///     .organizations()
    ///     .create_organization(&CreateOrganizationParams {
    ///         name: "Foo Corp",
    ///         domain_data: vec![DomainData {
    ///             domain: "foo-corp.com",
    ///             state: DomainDataState::Pending,
    ///         }],
    ///         external_id: Some("2fe01467-f7ea-4dd2-8b79-c2b4f56d0191"),
    ///         metadata: Some(Metadata::from([(
    ///             "tier".to_string(),
    ///             "diamond".to_string(),
    ///         )])),
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

    use crate::organizations::{DomainDataState, OrganizationId};
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
                    "external_id": "2fe01467-f7ea-4dd2-8b79-c2b4f56d0191",
                    "metadata": {
                        "tier": "diamond"
                    },
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z",
                    "domains": [
                         {
                            "object": "organization_domain",
                            "id": "org_domain_01EHZNVPK2QXHMVWCEDQEKY69A",
                            "domain": "foo-corp.com",
                            "organization_id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                            "state": "pending",
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
                domain_data: vec![DomainData {
                    domain: "foo-corp.com",
                    state: DomainDataState::Pending,
                }],
                external_id: Some("2fe01467-f7ea-4dd2-8b79-c2b4f56d0191"),
                metadata: Some(Metadata::from([(
                    "tier".to_string(),
                    "diamond".to_string(),
                )])),
            })
            .await
            .unwrap();

        assert_eq!(
            organization.id,
            OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT")
        )
    }
}
