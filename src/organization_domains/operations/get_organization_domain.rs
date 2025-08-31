use async_trait::async_trait;
use thiserror::Error;

use crate::organization_domains::{OrganizationDomain, OrganizationDomainId, OrganizationDomains};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetOrganizationDomain`].
#[derive(Debug, Error)]
pub enum GetOrganizationDomainError {}

impl From<GetOrganizationDomainError> for WorkOsError<GetOrganizationDomainError> {
    fn from(err: GetOrganizationDomainError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get an Organization Domain](https://workos.com/docs/reference/domain-verification/get)
#[async_trait]
pub trait GetOrganizationDomain {
    /// Get the details of an existing organization domain.
    ///
    /// [WorkOS Docs: Get an Organization Domain](https://workos.com/docs/reference/domain-verification/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organization_domains::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetOrganizationDomainError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_domain = workos
    ///     .organization_domains()
    ///     .get_organization_domain(&OrganizationDomainId::from("org_domain_01HEJXJSTVEDT7T58BM70FMFET"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_organization_domain(
        &self,
        id: &OrganizationDomainId,
    ) -> WorkOsResult<OrganizationDomain, GetOrganizationDomainError>;
}

#[async_trait]
impl GetOrganizationDomain for OrganizationDomains<'_> {
    async fn get_organization_domain(
        &self,
        id: &OrganizationDomainId,
    ) -> WorkOsResult<OrganizationDomain, GetOrganizationDomainError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/organization_domains/{id}"))?;

        let organization_domain = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<OrganizationDomain>()
            .await?;

        Ok(organization_domain)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_organization_domain_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/organization_domains/org_domain_01HEJXJSTVEDT7T58BM70FMFET",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
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
            .get_organization_domain(&OrganizationDomainId::from(
                "org_domain_01HEJXJSTVEDT7T58BM70FMFET",
            ))
            .await
            .unwrap();

        assert_eq!(
            organization_domain.id,
            OrganizationDomainId::from("org_domain_01HEJXJSTVEDT7T58BM70FMFET")
        )
    }
}
