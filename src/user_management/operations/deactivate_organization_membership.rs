use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{OrganizationMembership, OrganizationMembershipId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`DeactivateOrganizationMembership`].
#[derive(Debug, Error)]
pub enum DeactivateOrganizationMembershipError {}

impl From<DeactivateOrganizationMembershipError> for WorkOsError<DeactivateOrganizationMembershipError> {
    fn from(err: DeactivateOrganizationMembershipError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Deactivate Organization Membership](https://workos.com/docs/reference/authkit/organization-membership#deactivate-organization-membership)
#[async_trait]
pub trait DeactivateOrganizationMembership {
    /// Deactivates an [`OrganizationMembership`].
    ///
    /// [WorkOS Docs: Deactivate Organization Membership](https://workos.com/docs/reference/authkit/organization-membership#deactivate-organization-membership)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos_sdk::WorkOsResult;
    /// # use workos_sdk::user_management::*;
    /// use workos_sdk::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), DeactivateOrganizationMembershipError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_membership = workos
    ///     .user_management()
    ///     .deactivate_organization_membership(&OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn deactivate_organization_membership(
        &self,
        organization_membership_id: &OrganizationMembershipId,
    ) -> WorkOsResult<OrganizationMembership, DeactivateOrganizationMembershipError>;
}

#[async_trait]
impl DeactivateOrganizationMembership for UserManagement<'_> {
    async fn deactivate_organization_membership(
        &self,
        organization_membership_id: &OrganizationMembershipId,
    ) -> WorkOsResult<OrganizationMembership, DeactivateOrganizationMembershipError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/organization_memberships/{}/deactivate", organization_membership_id))?;
        
        let organization_membership = self
            .workos
            .client()
            .put(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()?
            .json::<OrganizationMembership>()
            .await?;

        Ok(organization_membership)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::user_management::{OrganizationMembershipId, OrganizationMembershipStatus};
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_deactivate_organization_membership_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("PUT", "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5/deactivate")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "object": "organization_membership",
                    "id": "om_01E4ZCR3C56J083X43JQXF3JK5",
                    "user_id": "user_01E4ZCR3C56J083X43JQXF3JK5",
                    "organization_id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                    "role": {
                        "slug": "admin"
                    },
                    "status": "inactive",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization_membership = workos
            .user_management()
            .deactivate_organization_membership(&OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5"))
            .await
            .unwrap();

        assert_eq!(
            organization_membership.id,
            OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5")
        );
        assert_eq!(organization_membership.status, OrganizationMembershipStatus::Inactive);
    }
}