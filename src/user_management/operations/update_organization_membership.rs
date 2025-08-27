use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{OrganizationMembership, OrganizationMembershipId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`UpdateOrganizationMembership`].
#[derive(Debug, Serialize)]
pub struct UpdateOrganizationMembershipParams<'a> {
    /// The unique ID of the organization membership.
    #[serde(skip_serializing)]
    pub organization_membership_id: &'a OrganizationMembershipId,

    /// The unique role identifier.
    pub role_slug: &'a str,
}

/// An error returned from [`UpdateOrganizationMembership`].
#[derive(Debug, Error)]
pub enum UpdateOrganizationMembershipError {}

impl From<UpdateOrganizationMembershipError> for WorkOsError<UpdateOrganizationMembershipError> {
    fn from(err: UpdateOrganizationMembershipError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Update an organization membership](https://workos.com/docs/reference/user-management/organization-membership/update)
#[async_trait]
pub trait UpdateOrganizationMembership {
    /// Update the details of an existing organization membership.
    ///
    /// [WorkOS Docs: Update an organization membership](https://workos.com/docs/reference/user-management/organization-membership/update)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), UpdateOrganizationMembershipError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_membership = workos
    ///     .user_management()
    ///     .update_organization_membership(&UpdateOrganizationMembershipParams {
    ///         organization_membership_id: &OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5"),
    ///         role_slug: "admin",
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn update_organization_membership(
        &self,
        params: &UpdateOrganizationMembershipParams<'_>,
    ) -> WorkOsResult<OrganizationMembership, UpdateOrganizationMembershipError>;
}

#[async_trait]
impl UpdateOrganizationMembership for UserManagement<'_> {
    async fn update_organization_membership(
        &self,
        params: &UpdateOrganizationMembershipParams<'_>,
    ) -> WorkOsResult<OrganizationMembership, UpdateOrganizationMembershipError> {
        let url = self.workos.base_url().join(&format!(
            "/user_management/organization_memberships/{id}",
            id = params.organization_membership_id
        ))?;
        let organization_membership = self
            .workos
            .client()
            .put(url)
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

    use crate::user_management::OrganizationMembershipId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_update_organization_membership_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "PUT",
                "/user_management/organization_memberships/om_01E4ZCR3C56J083X43JQXF3JK5",
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
                        "slug": "admin"
                    },
                    "status": "active",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-27T19:07:33.278Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization_membership = workos
            .user_management()
            .update_organization_membership(&UpdateOrganizationMembershipParams {
                organization_membership_id: &OrganizationMembershipId::from(
                    "om_01E4ZCR3C56J083X43JQXF3JK5",
                ),
                role_slug: "admin",
            })
            .await
            .unwrap();

        assert_eq!(
            organization_membership.id,
            OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5")
        )
    }
}
