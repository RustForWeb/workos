use async_trait::async_trait;
use thiserror::Error;

use crate::organization_domains::{OrganizationDomain, OrganizationDomainId, OrganizationDomains};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`VerifyOrganizationDomain`].
#[derive(Debug, Error)]
pub enum VerifyOrganizationDomainError {}

impl From<VerifyOrganizationDomainError> for WorkOsError<VerifyOrganizationDomainError> {
    fn from(err: VerifyOrganizationDomainError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Verify an Organization Domain](https://workos.com/docs/reference/domain-verification/verify)
#[async_trait]
pub trait VerifyOrganizationDomain {
    /// Initiates verification process for an Organization Domain.
    ///
    /// [WorkOS Docs: Verify an Organization Domain](https://workos.com/docs/reference/domain-verification/verify)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organization_domains::*;
    /// use workos::{ApiKey, Metadata, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), VerifyOrganizationDomainError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_domain = workos
    ///     .organization_domains()
    ///     .verify_organization_domain(&OrganizationDomainId::from(
    ///         "org_domain_01HEJXJSTVEDT7T58BM70FMFET",
    ///     ))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn verify_organization_domain(
        &self,
        organization_domain_id: &OrganizationDomainId,
    ) -> WorkOsResult<OrganizationDomain, VerifyOrganizationDomainError>;
}

#[async_trait]
impl VerifyOrganizationDomain for OrganizationDomains<'_> {
    async fn verify_organization_domain(
        &self,
        organization_domain_id: &OrganizationDomainId,
    ) -> WorkOsResult<OrganizationDomain, VerifyOrganizationDomainError> {
        let url = self.workos.base_url().join(&format!(
            "/organization_domains/{organization_domain_id}/verify",
        ))?;

        let organization = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
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
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_verify_organization_domain_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "POST",
                "/organization_domains/org_domain_01HEJXJSTVEDT7T58BM70FMFET/verify",
            )
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
                    "verification_token": "oNKzjqppp347rDBgLA5dTo8uA",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization_domain = workos
            .organization_domains()
            .verify_organization_domain(&OrganizationDomainId::from(
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
