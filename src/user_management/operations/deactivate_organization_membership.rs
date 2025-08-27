use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{OrganizationMembership, OrganizationMembershipId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`DeactivateOrganizationMembership`].
#[derive(Debug, Serialize)]
pub struct DeactivateOrganizationMembershipParams<'a> {
    /// The unique ID of the organization membership.
    pub organization_membership_id: &'a OrganizationMembershipId,
}

/// An error returned from [`DeactivateOrganizationMembership`].
#[derive(Debug, Error)]
pub enum DeactivateOrganizationMembershipError {}

impl From<DeactivateOrganizationMembershipError>
    for WorkOsError<DeactivateOrganizationMembershipError>
{
    fn from(err: DeactivateOrganizationMembershipError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Deactivate an organization membership](https://workos.com/docs/reference/user-management/organization-membership/deactivate)
#[async_trait]
pub trait DeactivateOrganizationMembership {
    /// Deactivates an `active` organization membership.
    ///
    /// [WorkOS Docs: Deactivate an organization membership](https://workos.com/docs/reference/user-management/organization-membership/deactivate)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), DeactivateOrganizationMembershipError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_membership = workos
    ///     .user_management()
    ///     .deactivate_organization_membership(&DeactivateOrganizationMembershipParams {
    ///         organization_membership_id: &OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn deactivate_organization_membership(
        &self,
        params: &DeactivateOrganizationMembershipParams<'_>,
    ) -> WorkOsResult<OrganizationMembership, DeactivateOrganizationMembershipError>;
}

#[async_trait]
impl DeactivateOrganizationMembership for UserManagement<'_> {
    async fn deactivate_organization_membership(
        &self,
        params: &DeactivateOrganizationMembershipParams<'_>,
    ) -> WorkOsResult<OrganizationMembership, DeactivateOrganizationMembershipError> {
        let url = self.workos.base_url().join(&format!(
            "/user_management/organization_memberships/{id}/deactivate",
            id = params.organization_membership_id
        ))?;
        let organization_membership = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
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
    use crate::{ApiKey, KnownOrUnknown, WorkOs};

    use super::*;

    #[tokio::test]
    async fn deactivate_organization_membership_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "POST",
                "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5/deactivate",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "object": "organization_membership",
                    "id": "om_01E4ZCR3C56J083X43JQXF3JK5",
                    "user_id": "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
                    "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                    "role": {
                        "slug": "member"
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
            .deactivate_organization_membership(&DeactivateOrganizationMembershipParams {
                organization_membership_id: &OrganizationMembershipId::from(
                    "om_01E4ZCR3C56J083X43JQXF3JK5",
                ),
            })
            .await
            .unwrap();

        assert_eq!(
            organization_membership.id,
            OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5")
        );
        assert_eq!(
            organization_membership.status,
            KnownOrUnknown::Known(OrganizationMembershipStatus::Inactive)
        );
    }
}
