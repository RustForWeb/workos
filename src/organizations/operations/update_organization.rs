use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::{DomainData, Organization, OrganizationId, Organizations};
use crate::{Metadata, ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`UpdateOrganization`].
#[derive(Debug, Serialize)]
pub struct UpdateOrganizationParams<'a> {
    /// The ID of the organization passed in the URL.
    #[serde(skip_serializing)]
    pub organization_id: &'a OrganizationId,

    /// A descriptive name for the Organization.
    ///
    /// This field does not need to be unique.
    pub name: Option<&'a str>,

    /// The domains of the organization.
    pub domain_data: Option<Vec<DomainData<'a>>>,

    /// The Stripe customer ID associated with this organization.
    pub stripe_customer_id: Option<&'a str>,

    /// The external ID of the Organization.
    pub external_id: Option<&'a str>,

    /// Object containing metadata key/value pairs associated with the Organization.
    pub metadata: Option<Metadata>,
}

/// An error returned from [`UpdateOrganization`].
#[derive(Debug, Error)]
pub enum UpdateOrganizationError {}

impl From<UpdateOrganizationError> for WorkOsError<UpdateOrganizationError> {
    fn from(err: UpdateOrganizationError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Update an Organization](https://workos.com/docs/reference/organization/update)
#[async_trait]
pub trait UpdateOrganization {
    /// Updates an organization in the current environment.
    ///
    /// [WorkOS Docs: Update an Organization](https://workos.com/docs/reference/organization/update)
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
    /// # async fn run() -> WorkOsResult<(), UpdateOrganizationError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization = workos
    ///     .organizations()
    ///     .update_organization(&UpdateOrganizationParams {
    ///         organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
    ///         name: Some("Foo Corp"),
    ///         domain_data: Some(vec![DomainData {
    ///             domain: "foo-corp.com",
    ///             state: DomainDataState::Verified,
    ///         }]),
    ///         stripe_customer_id: Some("cus_R9qWAGMQ6nGE7V"),
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
    async fn update_organization(
        &self,
        params: &UpdateOrganizationParams<'_>,
    ) -> WorkOsResult<Organization, UpdateOrganizationError>;
}

#[async_trait]
impl UpdateOrganization for Organizations<'_> {
    async fn update_organization(
        &self,
        params: &UpdateOrganizationParams<'_>,
    ) -> WorkOsResult<Organization, UpdateOrganizationError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/organizations/{id}", id = params.organization_id))?;

        let organization = self
            .workos
            .client()
            .put(url)
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
    use crate::{ApiKey, Metadata, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_update_organization_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("PUT", "/organizations/org_01EHZNVPK3SFK441A1RGBFSHRT")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
            .with_body(
                json!({
                    "id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                    "object": "organization",
                    "name": "Foo Corp",
                    "allow_profiles_outside_organization": false,
                    "stripe_customer_id": "cus_R9qWAGMQ6nGE7V",
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
            .update_organization(&UpdateOrganizationParams {
                organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
                name: Some("Foo Corp"),
                domain_data: Some(vec![DomainData {
                    domain: "foo-corp.com",
                    state: DomainDataState::Verified,
                }]),
                stripe_customer_id: Some("cus_R9qWAGMQ6nGE7V"),
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
