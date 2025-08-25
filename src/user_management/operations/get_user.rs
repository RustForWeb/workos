use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{User, UserId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetUser`].
#[derive(Debug, Error)]
pub enum GetUserError {}

impl From<GetUserError> for WorkOsError<GetUserError> {
    fn from(err: GetUserError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get a user](https://workos.com/docs/reference/user-management/user/get)
#[async_trait]
pub trait GetUser {
    /// Get the details of an existing user.
    ///
    /// [WorkOS Docs: Get a user](https://workos.com/docs/reference/user-management/user/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetUserError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let user = workos
    ///     .user_management()
    ///     .get_user(&UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_user(&self, id: &UserId) -> WorkOsResult<User, GetUserError>;
}

#[async_trait]
impl GetUser for UserManagement<'_> {
    async fn get_user(&self, id: &UserId) -> WorkOsResult<User, GetUserError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/users/{id}"))?;
        let user = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<User>()
            .await?;

        Ok(user)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_user_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/user_management/users/user_01E4ZCR3C56J083X43JQXF3JK5",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
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
                })
                .to_string(),
            )
            .create_async()
            .await;

        let user = workos
            .user_management()
            .get_user(&UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
            .await
            .unwrap();

        assert_eq!(user.id, UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
    }
}
