use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{OrganizationMembership, OrganizationMembershipId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetOrganizationMembership`].
#[derive(Debug, Error)]
pub enum GetOrganizationMembershipError {}

impl From<GetOrganizationMembershipError> for WorkOsError<GetOrganizationMembershipError> {
    fn from(err: GetOrganizationMembershipError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get Organization Membership](https://workos.com/docs/reference/authkit/organization-membership#get-organization-membership)
#[async_trait]
pub trait GetOrganizationMembership {
    /// Retrieves an [`OrganizationMembership`] by ID.
    ///
    /// [WorkOS Docs: Get Organization Membership](https://workos.com/docs/reference/authkit/organization-membership#get-organization-membership)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos_sdk::WorkOsResult;
    /// # use workos_sdk::user_management::*;
    /// use workos_sdk::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetOrganizationMembershipError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_membership = workos
    ///     .user_management()
    ///     .get_organization_membership(&OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_organization_membership(
        &self,
        organization_membership_id: &OrganizationMembershipId,
    ) -> WorkOsResult<OrganizationMembership, GetOrganizationMembershipError>;
}

#[async_trait]
impl GetOrganizationMembership for UserManagement<'_> {
    async fn get_organization_membership(
        &self,
        organization_membership_id: &OrganizationMembershipId,
    ) -> WorkOsResult<OrganizationMembership, GetOrganizationMembershipError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/organization_memberships/{}", organization_membership_id))?;
        
        let organization_membership = self
            .workos
            .client()
            .get(url)
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

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_organization_membership_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5")
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
                    "status": "active",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization_membership = workos
            .user_management()
            .get_organization_membership(&OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5"))
            .await
            .unwrap();

        assert_eq!(
            organization_membership.id,
            OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5")
        );
    }
}