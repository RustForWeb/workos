use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organization_domains::{OrganizationDomainId, OrganizationDomains};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`DeleteOrganizationDomain`].
#[derive(Debug, Serialize)]
pub struct DeleteOrganizationDomainParams<'a> {
    /// The ID of the organization_domain.
    pub organization_domain_id: &'a OrganizationDomainId,
}

/// An error returned from [`DeleteOrganizationDomain`].
#[derive(Debug, Error)]
pub enum DeleteOrganizationDomainError {}

impl From<DeleteOrganizationDomainError> for WorkOsError<DeleteOrganizationDomainError> {
    fn from(err: DeleteOrganizationDomainError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Delete an Organization Domain](https://workos.com/docs/reference/domain-verification/delete)
#[async_trait]
pub trait DeleteOrganizationDomain {
    /// Permanently deletes an organization domain in the current environment. It cannot be undone.
    ///
    /// [WorkOS Docs: Delete an Organization Domain](https://workos.com/docs/reference/domain-verification/delete)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organization_domains::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), DeleteOrganizationDomainError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// workos
    ///     .organization_domains()
    ///     .delete_organization_domain(&DeleteOrganizationDomainParams {
    ///         organization_domain_id: &OrganizationDomainId::from("org_domain_01HEJXJSTVEDT7T58BM70FMFET"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete_organization_domain(
        &self,
        params: &DeleteOrganizationDomainParams<'_>,
    ) -> WorkOsResult<(), DeleteOrganizationDomainError>;
}

#[async_trait]
impl DeleteOrganizationDomain for OrganizationDomains<'_> {
    async fn delete_organization_domain(
        &self,
        params: &DeleteOrganizationDomainParams<'_>,
    ) -> WorkOsResult<(), DeleteOrganizationDomainError> {
        let url = self.workos.base_url().join(&format!(
            "/organization_domains/{id}",
            id = params.organization_domain_id
        ))?;

        self.workos
            .client()
            .delete(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use tokio;

    use super::*;
    use crate::{ApiKey, WorkOs};
    use matches::assert_matches;

    #[tokio::test]
    async fn it_calls_the_delete_organization_domain_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "DELETE",
                "/organization_domains/org_domain_01HEJXJSTVEDT7T58BM70FMFET",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(202)
            .create_async()
            .await;

        let result = workos
            .organization_domains()
            .delete_organization_domain(&DeleteOrganizationDomainParams {
                organization_domain_id: &OrganizationDomainId::from(
                    "org_domain_01HEJXJSTVEDT7T58BM70FMFET",
                ),
            })
            .await;

        assert_matches!(result, Ok(()));
    }
}
