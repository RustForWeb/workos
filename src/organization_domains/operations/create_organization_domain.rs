use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organization_domains::{OrganizationDomain, OrganizationDomains};
use crate::organizations::OrganizationId;
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`CreateOrganizationDomain`].
#[derive(Debug, Serialize)]
pub struct CreateOrganizationDomainParams<'a> {
    /// ID of the parent Organization.
    pub organization_id: &'a OrganizationId,

    /// Domain for the organization domain.
    pub domain: &'a str,
}

/// An error returned from [`CreateOrganizationDomain`].
#[derive(Debug, Error)]
pub enum CreateOrganizationDomainError {}

impl From<CreateOrganizationDomainError> for WorkOsError<CreateOrganizationDomainError> {
    fn from(err: CreateOrganizationDomainError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Create an Organization Domain](https://workos.com/docs/reference/domain-verification/create)
#[async_trait]
pub trait CreateOrganizationDomain {
    /// Creates a new Organization Domain.
    ///
    /// [WorkOS Docs: Create an Organization Domain](https://workos.com/docs/reference/domain-verification/create)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organization_domains::*;
    /// use workos::organizations::OrganizationId;
    /// use workos::{ApiKey, Metadata, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), CreateOrganizationDomainError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_domain = workos
    ///     .organization_domains()
    ///     .create_organization_domain(&CreateOrganizationDomainParams {
    ///         organization_id: &OrganizationId::from("org_01EHT88Z8J8795GZNQ4ZP1J81T"),
    ///         domain: "foo-corp.com",
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_organization_domain(
        &self,
        params: &CreateOrganizationDomainParams<'_>,
    ) -> WorkOsResult<OrganizationDomain, CreateOrganizationDomainError>;
}

#[async_trait]
impl CreateOrganizationDomain for OrganizationDomains<'_> {
    async fn create_organization_domain(
        &self,
        params: &CreateOrganizationDomainParams<'_>,
    ) -> WorkOsResult<OrganizationDomain, CreateOrganizationDomainError> {
        let url = self.workos.base_url().join("/organization_domains")?;

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
            .json::<OrganizationDomain>()
            .await?;

        Ok(organization)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::organization_domains::OrganizationDomainId;
    use crate::organizations::OrganizationId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_create_organization_domain_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/organization_domains")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
            .with_body(
                json!({
                    "object": "organization_domain",
                    "id": "org_domain_01HEJXJSTVEDT7T58BM70FMFET",
                    "organization_id": "org_01EHT88Z8J8795GZNQ4ZP1J81T",
                    "domain": "foo-corp.com",
                    "state": "pending",
                    "verification_strategy": "dns",
                    "verification_token": "aW5HQ8Sgps1y3LQyrShsFRo3F",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization_domain = workos
            .organization_domains()
            .create_organization_domain(&CreateOrganizationDomainParams {
                organization_id: &OrganizationId::from("org_01EHT88Z8J8795GZNQ4ZP1J81T"),
                domain: "foo-corp.com",
            })
            .await
            .unwrap();

        assert_eq!(
            organization_domain.id,
            OrganizationDomainId::from("org_domain_01HEJXJSTVEDT7T58BM70FMFET")
        )
    }
}
