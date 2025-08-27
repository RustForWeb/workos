use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::OrganizationId;
use crate::roles::{Role, Roles};
use crate::{ResponseExt, UnpaginatedList, WorkOsError, WorkOsResult};

/// The parameters for the [`ListOrganizationRoles`] function.
#[derive(Debug, Serialize)]
pub struct ListOrganizationRolesParams<'a> {
    /// The ID of the organization.
    #[serde(skip_serializing)]
    pub organization_id: &'a OrganizationId,
}

/// An error returned from [`ListOrganizationRoles`].
#[derive(Debug, Error)]
pub enum ListOrganizationRolesError {}

impl From<ListOrganizationRolesError> for WorkOsError<ListOrganizationRolesError> {
    fn from(err: ListOrganizationRolesError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List roles for an organization](https://workos.com/docs/reference/roles/list-for-organization)
#[async_trait]
pub trait ListOrganizationRoles {
    /// Get a list of all roles for the provided organization in priority order.
    ///
    /// Includes all environment and organization roles.
    ///
    /// [WorkOS Docs: List roles for an organization](https://workos.com/docs/reference/roles/list-for-organization)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::roles::*;
    /// use workos::{ApiKey, WorkOs};
    /// use workos::organizations::OrganizationId;
    ///
    /// # async fn run() -> WorkOsResult<(), ListOrganizationRolesError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let roles = workos
    ///     .roles()
    ///     .list_organization_roles(&ListOrganizationRolesParams {
    ///         organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_organization_roles(
        &self,
        params: &ListOrganizationRolesParams,
    ) -> WorkOsResult<UnpaginatedList<Role>, ListOrganizationRolesError>;
}

#[async_trait]
impl ListOrganizationRoles for Roles<'_> {
    async fn list_organization_roles(
        &self,
        params: &ListOrganizationRolesParams,
    ) -> WorkOsResult<UnpaginatedList<Role>, ListOrganizationRolesError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/organizations/{}/roles", params.organization_id))?;

        println!("{url}");

        let roles = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<UnpaginatedList<Role>>()
            .await?;

        Ok(roles)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::organizations::OrganizationId;
    use crate::roles::RoleId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_list_organization_roles_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/organizations/org_01EHZNVPK3SFK441A1RGBFSHRT/roles")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "data": [
                        {
                            "id": "role_01EHZNVPK3SFK441A1RGBFSRTY",
                            "object": "role",
                            "name": "Admin",
                            "slug": "admin",
                            "description": "Access to all resources",
                            "permissions": ["posts:read", "posts:write"],
                            "type": "EnvironmentRole",
                            "created_at": "2021-06-25T19:07:33.155Z",
                            "updated_at": "2021-06-25T19:07:33.155Z"
                        },
                        {
                            "id": "role_01EHZNVPK3SFK441A1RGBFSHRT",
                            "object": "role",
                            "name": "Member",
                            "slug": "member",
                            "description": "Access to basic resources",
                            "permissions": [],
                            "type": "EnvironmentRole",
                            "created_at": "2021-06-25T19:07:33.155Z",
                            "updated_at": "2021-06-25T19:07:33.155Z"
                        },
                        {
                            "id": "role_01EHZNVPK3SFK441A1RGBFSYUP",
                            "object": "role",
                            "name": "Billing Manager",
                            "slug": "billing-manager",
                            "description": "Access to billing resources",
                            "permissions": ["billing:manage"],
                            "type": "OrganizationRole",
                            "created_at": "2021-06-25T19:07:33.155Z",
                            "updated_at": "2021-06-25T19:07:33.155Z"
                        }
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .roles()
            .list_organization_roles(&ListOrganizationRolesParams {
                organization_id: &OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"),
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|user| user.id),
            Some(RoleId::from("role_01EHZNVPK3SFK441A1RGBFSRTY"))
        )
    }
}
