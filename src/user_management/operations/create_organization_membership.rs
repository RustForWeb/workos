use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::OrganizationId;
use crate::roles::RoleSlug;
use crate::user_management::{OrganizationMembership, UserId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`CreateOrganizationMembership`].
#[derive(Debug, Serialize)]
pub struct CreateOrganizationMembershipParams<'a> {
    /// The ID of the user.
    pub user_id: &'a UserId,

    /// The ID of the organization which the user belongs to.
    pub organization_id: &'a OrganizationId,

    /// The unique role identifier.
    ///
    /// Defaults to `member`.
    pub role_slug: Option<&'a RoleSlug>,
}

/// An error returned from [`CreateOrganizationMembership`].
#[derive(Debug, Error)]
pub enum CreateOrganizationMembershipError {}

impl From<CreateOrganizationMembershipError> for WorkOsError<CreateOrganizationMembershipError> {
    fn from(err: CreateOrganizationMembershipError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Create an organization membership](https://workos.com/docs/reference/user-management/organization-membership/create)
#[async_trait]
pub trait CreateOrganizationMembership {
    /// Creates a new `active` organization membership for the given organization and user.
    ///
    /// Calling this API with an organization and user that match an `inactive` organization membership will activate the membership with the specified role.
    ///
    /// [WorkOS Docs: Create an organization membership](https://workos.com/docs/reference/user-management/organization-membership/create)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organizations::OrganizationId;
    /// # use workos::roles::RoleSlug;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), CreateOrganizationMembershipError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_membership = workos
    ///     .user_management()
    ///     .create_organization_membership(&CreateOrganizationMembershipParams {
    ///          user_id: &UserId::from("user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E"),
    ///          organization_id: &OrganizationId::from("org_01E4ZCR3C56J083X43JQXF3JK5"),
    ///          role_slug: Some(&RoleSlug::from("admin")),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_organization_membership(
        &self,
        params: &CreateOrganizationMembershipParams<'_>,
    ) -> WorkOsResult<OrganizationMembership, CreateOrganizationMembershipError>;
}

#[async_trait]
impl CreateOrganizationMembership for UserManagement<'_> {
    async fn create_organization_membership(
        &self,
        params: &CreateOrganizationMembershipParams<'_>,
    ) -> WorkOsResult<OrganizationMembership, CreateOrganizationMembershipError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/organization_membership")?;
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

    use crate::user_management::OrganizationMembershipId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_create_organization_membership_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/organization_membership")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
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
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization_membership = workos
            .user_management()
            .create_organization_membership(&CreateOrganizationMembershipParams {
                user_id: &UserId::from("user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E"),
                organization_id: &OrganizationId::from("org_01E4ZCR3C56J083X43JQXF3JK5"),
                role_slug: Some(&RoleSlug::from("admin")),
            })
            .await
            .unwrap();

        assert_eq!(
            organization_membership.id,
            OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5")
        )
    }
}
