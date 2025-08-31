use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::{OrganizationId, Organizations};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`DeleteOrganization`].
#[derive(Debug, Serialize)]
pub struct DeleteOrganizationParams<'a> {
    /// The ID of the organization.
    pub organization_id: &'a OrganizationId,
}

/// An error returned from [`DeleteOrganization`].
#[derive(Debug, Error)]
pub enum DeleteOrganizationError {}

impl From<DeleteOrganizationError> for WorkOsError<DeleteOrganizationError> {
    fn from(err: DeleteOrganizationError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Delete an Organization](https://workos.com/docs/reference/organization/delete)
#[async_trait]
pub trait DeleteOrganization {
    /// Permanently deletes an organization in the current environment. It cannot be undone.
    ///
    /// [WorkOS Docs: Delete an Organization](https://workos.com/docs/reference/organization/delete)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organizations::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), DeleteOrganizationError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// workos
    ///     .organizations()
    ///     .delete_organization(&DeleteOrganizationParams {
    ///         organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete_organization(
        &self,
        params: &DeleteOrganizationParams<'_>,
    ) -> WorkOsResult<(), DeleteOrganizationError>;
}

#[async_trait]
impl DeleteOrganization for Organizations<'_> {
    async fn delete_organization(
        &self,
        params: &DeleteOrganizationParams<'_>,
    ) -> WorkOsResult<(), DeleteOrganizationError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/organizations/{id}", id = params.organization_id))?;

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
    async fn it_calls_the_delete_organization_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("DELETE", "/organizations/org_01EHZNVPK3SFK441A1RGBFSHRT")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(202)
            .create_async()
            .await;

        let result = workos
            .organizations()
            .delete_organization(&DeleteOrganizationParams {
                organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
            })
            .await;

        assert_matches!(result, Ok(()));
    }
}
