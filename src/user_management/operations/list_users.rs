use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::OrganizationId;
use crate::user_management::{User, UserManagement};
use crate::{PaginatedList, PaginationParams, ResponseExt, WorkOsError, WorkOsResult};

/// Parameters for the [`ListUsers`] function.
#[derive(Debug, Default, Serialize)]
pub struct ListUsersParams<'a> {
    /// The pagination parameters to use when listing users.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,

    /// Filter users by their email.
    pub email: Option<&'a str>,

    /// Filter users by the organization they are members of.
    pub organization_id: Option<&'a OrganizationId>,
}

/// An error returned from [`ListUsers`].
#[derive(Debug, Error)]
pub enum ListUsersError {}

impl From<ListUsersError> for WorkOsError<ListUsersError> {
    fn from(err: ListUsersError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List Users](https://workos.com/docs/reference/user-management/user/list)
#[async_trait]
pub trait ListUsers {
    /// Retrieves a list of [`User`]s.
    ///
    /// [WorkOS Docs: List Users](https://workos.com/docs/reference/user-management/user/list)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ListUsersError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let paginated_users = workos
    ///     .user_management()
    ///     .list_users(&ListUsersParams {
    ///         email: Some("marcelina.davis@example.com"),
    ///         ..Default::default()
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_users(
        &self,
        params: &ListUsersParams<'_>,
    ) -> WorkOsResult<PaginatedList<User>, ListUsersError>;
}

#[async_trait]
impl ListUsers for UserManagement<'_> {
    async fn list_users(
        &self,
        params: &ListUsersParams<'_>,
    ) -> WorkOsResult<PaginatedList<User>, ListUsersError> {
        let url = self.workos.base_url().join("/user_management/users")?;
        let users = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<User>>()
            .await?;

        Ok(users)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::user_management::UserId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_list_users_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/users")
            .match_query(Matcher::UrlEncoded("order".to_string(), "desc".to_string()))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
                        "object": "user",
                        "id": "user_01E4ZCR3C56J083X43JQXF3JK5",
                        "email": "marcelina.davis@example.com",
                        "first_name": "Marcelina",
                        "last_name": "Davis",
                        "email_verified": true,
                        "profile_picture_url": "https://workoscdn.com/images/v1/123abc",
                        "last_sign_in_at": "2021-06-25T19:07:33.155Z",
                        "external_id": "f1ffa2b2-c20b-4d39-be5c-212726e11222",
                        "metadata": {
                          "language": "en"
                        },
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    }
                  ],
                  "list_metadata": {
                    "before": "user_01E4ZCR3C56J083X43JQXF3JK5",
                    "after": "user_01EJBGJT2PC6638TN5Y380M40Z"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_users(&Default::default())
            .await
            .unwrap();

        assert_eq!(
            paginated_list.metadata.after,
            Some("user_01EJBGJT2PC6638TN5Y380M40Z".to_string())
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_users_endpoint_with_an_email() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/users")
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
                        "object": "user",
                        "id": "user_01E4ZCR3C56J083X43JQXF3JK5",
                        "email": "marcelina.davis@example.com",
                        "first_name": "Marcelina",
                        "last_name": "Davis",
                        "email_verified": true,
                        "profile_picture_url": "https://workoscdn.com/images/v1/123abc",
                        "last_sign_in_at": "2021-06-25T19:07:33.155Z",
                        "external_id": "f1ffa2b2-c20b-4d39-be5c-212726e11222",
                        "metadata": {
                          "language": "en"
                        },
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    }
                  ],
                  "list_metadata": {
                    "before": "user_01E4ZCR3C56J083X43JQXF3JK5",
                    "after": "user_01EJBGJT2PC6638TN5Y380M40Z"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_users(&ListUsersParams {
                email: Some("marcelina.davis@example.com"),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|user| user.id),
            Some(UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_users_endpoint_with_an_organization_id() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/users")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".to_string(), "desc".to_string()),
                Matcher::UrlEncoded(
                    "organization_id".to_string(),
                    "org_01EHZNVPK3SFK441A1RGBFSHRT".to_string(),
                ),
            ]))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
                        "object": "user",
                        "id": "user_01E4ZCR3C56J083X43JQXF3JK5",
                        "email": "marcelina.davis@example.com",
                        "first_name": "Marcelina",
                        "last_name": "Davis",
                        "email_verified": true,
                        "profile_picture_url": "https://workoscdn.com/images/v1/123abc",
                        "last_sign_in_at": "2021-06-25T19:07:33.155Z",
                        "external_id": "f1ffa2b2-c20b-4d39-be5c-212726e11222",
                        "metadata": {
                          "language": "en"
                        },
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    }
                  ],
                  "list_metadata": {
                    "before": "user_01E4ZCR3C56J083X43JQXF3JK5",
                    "after": "user_01EJBGJT2PC6638TN5Y380M40Z"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_users(&ListUsersParams {
                organization_id: Some(&OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT")),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|user| user.id),
            Some(UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
        )
    }
}
