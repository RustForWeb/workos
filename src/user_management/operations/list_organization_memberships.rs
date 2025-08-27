use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::OrganizationId;
use crate::user_management::{OrganizationMembership, UserId, UserManagement};
use crate::{
    PaginatedList, PaginationParams, ResponseExt, UrlEncodableVec, WorkOsError, WorkOsResult,
};

/// A filter for [`ListOrganizationMemberships`].
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ListOrganizationMembershipsFilter<'a> {
    /// Retrieve organization memberships from the specified organization.
    Organization {
        /// The ID of the organization which the user belongs to.
        organization_id: &'a OrganizationId,
    },

    /// Retrieve organization memberships a specified user is a member of.
    User {
        /// The ID of the user.
        user_id: &'a UserId,
    },
}

/// The statuses to filter the organization memberships by.
#[derive(Debug, Serialize)]
pub struct StatusFilters<'a>(UrlEncodableVec<&'a str>);

impl<'a> From<Vec<&'a str>> for StatusFilters<'a> {
    fn from(statuses: Vec<&'a str>) -> Self {
        Self(statuses.into())
    }
}

/// The parameters for the [`ListOrganizationMemberships`] function.
#[derive(Debug, Serialize)]
pub struct ListOrganizationMembershipsParams<'a> {
    /// The pagination parameters to use when listing organization memberships.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,

    /// The filter to use when listing directory groupss.
    #[serde(flatten)]
    pub filter: ListOrganizationMembershipsFilter<'a>,

    /// Filter by the status of the organization membership.
    pub statuses: Option<StatusFilters<'a>>,
}

/// An error returned from [`ListOrganizationMemberships`].
#[derive(Debug, Error)]
pub enum ListOrganizationMembershipsError {}

impl From<ListOrganizationMembershipsError> for WorkOsError<ListOrganizationMembershipsError> {
    fn from(err: ListOrganizationMembershipsError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List organization memberships](https://workos.com/docs/reference/user-management/organization_membership/list)
#[async_trait]
pub trait ListOrganizationMemberships {
    /// Get a list of all organization memberships matching the criteria specified.
    ///
    /// [WorkOS Docs: List organization memberships](https://workos.com/docs/reference/user-management/organization_membership/list)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    /// use workos::organizations::OrganizationId;
    ///
    /// # async fn run() -> WorkOsResult<(), ListOrganizationMembershipsError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization_memberships = workos
    ///     .user_management()
    ///     .list_organization_memberships(&ListOrganizationMembershipsParams {
    ///         pagination: Default::default(),
    ///         filter: ListOrganizationMembershipsFilter::Organization {
    ///             organization_id: &OrganizationId::from("org_01E4ZCR3C56J083X43JQXF3JK5"),
    ///         },
    ///         statuses: None,
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_organization_memberships(
        &self,
        params: &ListOrganizationMembershipsParams,
    ) -> WorkOsResult<PaginatedList<OrganizationMembership>, ListOrganizationMembershipsError>;
}

#[async_trait]
impl ListOrganizationMemberships for UserManagement<'_> {
    async fn list_organization_memberships(
        &self,
        params: &ListOrganizationMembershipsParams,
    ) -> WorkOsResult<PaginatedList<OrganizationMembership>, ListOrganizationMembershipsError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/organization_memberships")?;

        let organization_memberships = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<OrganizationMembership>>()
            .await?;

        Ok(organization_memberships)
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
    async fn it_calls_the_list_organization_memberships_endpoint_with_an_user_id() {
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
                    "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E".to_string(),
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
                            "user_id": "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
                            "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                            "organization_name": "Acme, Inc.",
                            "role": {
                                "slug": "member"
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
                pagination: Default::default(),
                filter: ListOrganizationMembershipsFilter::User {
                    user_id: &UserId::from("user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E"),
                },
                statuses: None,
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|user| user.id),
            Some(OrganizationMembershipId::from(
                "om_01E4ZCR3C56J083X43JQXF3JK5"
            ))
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_organization_memberships_endpoint_with_an_organization_id() {
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
                    "organization_id".to_string(),
                    "org_01E4ZCR3C56J083X43JQXF3JK5".to_string(),
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
                            "user_id": "user_01E4ZCR3C5A4QZ2Z2JQXGKZJ9E",
                            "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                            "organization_name": "Acme, Inc.",
                            "role": {
                                "slug": "member"
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
                pagination: Default::default(),
                filter: ListOrganizationMembershipsFilter::Organization {
                    organization_id: &OrganizationId::from("org_01E4ZCR3C56J083X43JQXF3JK5"),
                },
                statuses: None,
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|user| user.id),
            Some(OrganizationMembershipId::from(
                "om_01E4ZCR3C56J083X43JQXF3JK5"
            ))
        )
    }
}
