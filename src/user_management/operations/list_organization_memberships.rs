use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::OrganizationId;
use crate::user_management::{OrganizationMembership, OrganizationMembershipStatus, UserId, UserManagement};
use crate::{PaginatedList, PaginationParams, ResponseExt, WorkOsError, WorkOsResult};

/// Parameters for the [`ListOrganizationMemberships`] function.
#[derive(Debug, Default, Serialize)]
pub struct ListOrganizationMembershipsParams<'a> {
    /// The pagination parameters to use when listing organization memberships.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,

    /// Filter organization memberships by user ID.
    pub user_id: Option<&'a UserId>,

    /// Filter organization memberships by organization ID.
    pub organization_id: Option<&'a OrganizationId>,

    /// Filter organization memberships by status.
    #[serde(serialize_with = "serialize_statuses", skip_serializing_if = "Option::is_none")]
    pub statuses: Option<&'a [OrganizationMembershipStatus]>,
}

fn serialize_statuses<S>(
    statuses: &Option<&[OrganizationMembershipStatus]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize;
    
    match statuses {
        Some(statuses) => {
            let status_strings: Vec<String> = statuses
                .iter()
                .map(|s| match s {
                    OrganizationMembershipStatus::Active => "active".to_string(),
                    OrganizationMembershipStatus::Inactive => "inactive".to_string(),
                    OrganizationMembershipStatus::Pending => "pending".to_string(),
                })
                .collect();
            status_strings.serialize(serializer)
        }
        None => serializer.serialize_none(),
    }
}

/// An error returned from [`ListOrganizationMemberships`].
#[derive(Debug, Error)]
pub enum ListOrganizationMembershipsError {}

impl From<ListOrganizationMembershipsError> for WorkOsError<ListOrganizationMembershipsError> {
    fn from(err: ListOrganizationMembershipsError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List Organization Memberships](https://workos.com/docs/reference/authkit/organization-membership#list-organization-memberships)
#[async_trait]
pub trait ListOrganizationMemberships {
    /// Retrieves a list of [`OrganizationMembership`]s.
    ///
    /// [WorkOS Docs: List Organization Memberships](https://workos.com/docs/reference/authkit/organization-membership#list-organization-memberships)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos_sdk::WorkOsResult;
    /// # use workos_sdk::user_management::*;
    /// use workos_sdk::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ListOrganizationMembershipsError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let paginated_memberships = workos
    ///     .user_management()
    ///     .list_organization_memberships(&ListOrganizationMembershipsParams {
    ///         user_id: Some(&UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5")),
    ///         ..Default::default()
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_organization_memberships(
        &self,
        params: &ListOrganizationMembershipsParams<'_>,
    ) -> WorkOsResult<PaginatedList<OrganizationMembership>, ListOrganizationMembershipsError>;
}

#[async_trait]
impl ListOrganizationMemberships for UserManagement<'_> {
    async fn list_organization_memberships(
        &self,
        params: &ListOrganizationMembershipsParams<'_>,
    ) -> WorkOsResult<PaginatedList<OrganizationMembership>, ListOrganizationMembershipsError> {
        let url = self.workos.base_url().join("/user_management/organization_memberships")?;
        let memberships = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()?
            .json::<PaginatedList<OrganizationMembership>>()
            .await?;

        Ok(memberships)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::user_management::OrganizationMembershipId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_list_organization_memberships_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/organization_memberships")
            .match_query(Matcher::UrlEncoded("order".to_string(), "desc".to_string()))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
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
                    }
                  ],
                  "list_metadata": {
                    "before": "om_01E4ZCR3C56J083X43JQXF3JK5",
                    "after": "om_01EJBGJT2PC6638TN5Y380M40Z"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_organization_memberships(&Default::default())
            .await
            .unwrap();

        assert_eq!(
            paginated_list.metadata.after,
            Some("om_01EJBGJT2PC6638TN5Y380M40Z".to_string())
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_organization_memberships_endpoint_with_user_id() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/organization_memberships")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".to_string(), "desc".to_string()),
                Matcher::UrlEncoded(
                    "user_id".to_string(),
                    "user_01E4ZCR3C56J083X43JQXF3JK5".to_string(),
                ),
            ]))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
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
                    }
                  ],
                  "list_metadata": {
                    "before": "om_01E4ZCR3C56J083X43JQXF3JK5",
                    "after": "om_01EJBGJT2PC6638TN5Y380M40Z"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_organization_memberships(&ListOrganizationMembershipsParams {
                user_id: Some(&UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5")),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|membership| membership.id),
            Some(OrganizationMembershipId::from("om_01E4ZCR3C56J083X43JQXF3JK5"))
        )
    }
}