use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::OrganizationId;
use crate::user_management::{Invitation, UserManagement};
use crate::{PaginatedList, PaginationParams, ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for the [`ListInvitations`] function.
#[derive(Debug, Serialize, Default)]
pub struct ListInvitationsParams<'a> {
    /// The email address of the recipient.
    pub email: Option<&'a str>,

    /// The ID of the organization that the recipient will join.
    pub organization_id: Option<&'a OrganizationId>,

    /// The pagination parameters to use when listing invitations.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,
}

/// An error returned from [`ListInvitations`].
#[derive(Debug, Error)]
pub enum ListInvitationsError {}

impl From<ListInvitationsError> for WorkOsError<ListInvitationsError> {
    fn from(err: ListInvitationsError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List invitations](https://workos.com/docs/reference/user-management/invitation/list)
#[async_trait]
pub trait ListInvitations {
    /// Get a list of all the invitations matching the criteria specified.
    ///
    /// [WorkOS Docs: List invitations](https://workos.com/docs/reference/user-management/invitation/list)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    /// use workos::organizations::OrganizationId;
    ///
    /// # async fn run() -> WorkOsResult<(), ListInvitationsError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let invitations = workos
    ///     .user_management()
    ///     .list_invitations(&ListInvitationsParams {
    ///         email: Some("marcelina.davis@example.com"),
    ///         organization_id: Some(&OrganizationId::from("org_01E4ZCR3C56J083X43JQXF3JK5")),
    ///         ..Default::default()
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_invitations(
        &self,
        params: &ListInvitationsParams,
    ) -> WorkOsResult<PaginatedList<Invitation>, ListInvitationsError>;
}

#[async_trait]
impl ListInvitations for UserManagement<'_> {
    async fn list_invitations(
        &self,
        params: &ListInvitationsParams,
    ) -> WorkOsResult<PaginatedList<Invitation>, ListInvitationsError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/invitations")?;

        let invitations = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<Invitation>>()
            .await?;

        Ok(invitations)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::user_management::InvitationId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_list_invitations_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/invitations")
            .match_query(Matcher::UrlEncoded("order".to_string(), "desc".to_string()))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
                      "object": "invitation",
                      "id": "invitation_01E4ZCR3C56J083X43JQXF3JK5",
                      "email": "marcelina.davis@example.com",
                      "state": "pending",
                      "accepted_at": null,
                      "revoked_at": null,
                      "expires_at": "2021-07-01T19:07:33.155Z",
                      "token": "Z1uX3RbwcIl5fIGJJJCXXisdI",
                      "accept_invitation_url": "https://your-app.com/invite?invitation_token=Z1uX3RbwcIl5fIGJJJCXXisdI",
                      "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                      "inviter_user_id": "user_01HYGBX8ZGD19949T3BM4FW1C3",
                      "created_at": "2021-06-25T19:07:33.155Z",
                      "updated_at": "2021-06-25T19:07:33.155Z"
                    }
                  ],
                  "list_metadata": {
                    "before": "invitation_01E4ZCR3C56J083X43JQXF3JK5",
                    "after": "invitation_01EJBGJT2PC6638TN5Y380M40Z"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_invitations(&Default::default())
            .await
            .unwrap();

        assert_eq!(
            paginated_list.metadata.after,
            Some("invitation_01EJBGJT2PC6638TN5Y380M40Z".to_string())
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_invitations_endpoint_with_an_email() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/invitations")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".to_string(), "desc".to_string()),
                Matcher::UrlEncoded(
                    "email".to_string(),
                    "marcelina.davis@example.com".to_string(),
                ),
            ]))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
                      "object": "invitation",
                      "id": "invitation_01E4ZCR3C56J083X43JQXF3JK5",
                      "email": "marcelina.davis@example.com",
                      "state": "pending",
                      "accepted_at": null,
                      "revoked_at": null,
                      "expires_at": "2021-07-01T19:07:33.155Z",
                      "token": "Z1uX3RbwcIl5fIGJJJCXXisdI",
                      "accept_invitation_url": "https://your-app.com/invite?invitation_token=Z1uX3RbwcIl5fIGJJJCXXisdI",
                      "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                      "inviter_user_id": "user_01HYGBX8ZGD19949T3BM4FW1C3",
                      "created_at": "2021-06-25T19:07:33.155Z",
                      "updated_at": "2021-06-25T19:07:33.155Z"
                    }
                  ],
                  "list_metadata": {
                    "before": "invitation_01E4ZCR3C56J083X43JQXF3JK5",
                    "after": "invitation_01EJBGJT2PC6638TN5Y380M40Z"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_invitations(&ListInvitationsParams {
                email: Some("marcelina.davis@example.com"),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|user| user.id),
            Some(InvitationId::from("invitation_01E4ZCR3C56J083X43JQXF3JK5"))
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_invitations_endpoint_with_an_organization_id() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/invitations")
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
                      "object": "invitation",
                      "id": "invitation_01E4ZCR3C56J083X43JQXF3JK5",
                      "email": "marcelina.davis@example.com",
                      "state": "pending",
                      "accepted_at": null,
                      "revoked_at": null,
                      "expires_at": "2021-07-01T19:07:33.155Z",
                      "token": "Z1uX3RbwcIl5fIGJJJCXXisdI",
                      "accept_invitation_url": "https://your-app.com/invite?invitation_token=Z1uX3RbwcIl5fIGJJJCXXisdI",
                      "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                      "inviter_user_id": "user_01HYGBX8ZGD19949T3BM4FW1C3",
                      "created_at": "2021-06-25T19:07:33.155Z",
                      "updated_at": "2021-06-25T19:07:33.155Z"
                    }
                  ],
                  "list_metadata": {
                    "before": "invitation_01E4ZCR3C56J083X43JQXF3JK5",
                    "after": "invitation_01EJBGJT2PC6638TN5Y380M40Z"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_invitations(&ListInvitationsParams {
                organization_id: Some(&OrganizationId::from("org_01E4ZCR3C56J083X43JQXF3JK5")),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|user| user.id),
            Some(InvitationId::from("invitation_01E4ZCR3C56J083X43JQXF3JK5"))
        )
    }
}
