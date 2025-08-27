use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{OrganizationMembership, OrganizationMembershipId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`ReactivateOrganizationMembership`].
#[derive(Debug, Serialize)]
pub struct ReactivateOrganizationMembershipParams<'a> {
    /// The unique ID of the organization membership.
    pub organization_membership_id: &'a OrganizationMembershipId,
}

/// An error returned from [`ReactivateOrganizationMembership`].
#[derive(Debug, Error)]
pub enum ReactivateOrganizationMembershipError {}

impl From<ReactivateOrganizationMembershipError>
    for WorkOsError<ReactivateOrganizationMembershipError>
{
    fn from(err: ReactivateOrganizationMembershipError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Reactivate an organization membership](https://workos.com/docs/reference/user-management/organization-membership/reactivate)
#[async_trait]
pub trait ReactivateOrganizationMembership {
    /// Reactivates an `inactive` organization membership, retaining the pre-existing role.
    ///
    /// [WorkOS Docs: Reactivate an organization membership](https://workos.com/docs/reference/user-management/organization-membership/reactivate)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ReactivateOrganizationMembershipError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_membership = workos
    ///     .user_management()
    ///     .reactivate_organization_membership(&ReactivateOrganizationMembershipParams {
    ///         organization_membership_id: &OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn reactivate_organization_membership(
        &self,
        params: &ReactivateOrganizationMembershipParams<'_>,
    ) -> WorkOsResult<OrganizationMembership, ReactivateOrganizationMembershipError>;
}

#[async_trait]
impl ReactivateOrganizationMembership for UserManagement<'_> {
    async fn reactivate_organization_membership(
        &self,
        params: &ReactivateOrganizationMembershipParams<'_>,
    ) -> WorkOsResult<OrganizationMembership, ReactivateOrganizationMembershipError> {
        let url = self.workos.base_url().join(&format!(
            "/user_management/organization_memberships/{id}/reactivate",
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
    async fn reactivate_organization_membership_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "POST",
                "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5/reactivate",
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
            .reactivate_organization_membership(&ReactivateOrganizationMembershipParams {
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
            KnownOrUnknown::Known(OrganizationMembershipStatus::Active)
        );
    }
}
