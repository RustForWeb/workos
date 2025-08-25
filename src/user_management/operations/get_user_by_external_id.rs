use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{User, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetUserByExternalId`].
#[derive(Debug, Error)]
pub enum GetUserByExternalIdError {}

impl From<GetUserByExternalIdError> for WorkOsError<GetUserByExternalIdError> {
    fn from(err: GetUserByExternalIdError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get a user by external ID](https://workos.com/docs/reference/user-management/user/get-by-external-id)
#[async_trait]
pub trait GetUserByExternalId {
    /// Get the details of an existing user by an external identifier.
    ///
    /// [WorkOS Docs: Get a user by external ID](https://workos.com/docs/reference/user-management/user/get-by-external-id)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetUserByExternalIdError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let user = workos
    ///     .user_management()
    ///     .get_user_by_external_id("f1ffa2b2-c20b-4d39-be5c-212726e11222")
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_user_by_external_id(
        &self,
        external_id: &str,
    ) -> WorkOsResult<User, GetUserByExternalIdError>;
}

#[async_trait]
impl GetUserByExternalId for UserManagement<'_> {
    async fn get_user_by_external_id(
        &self,
        external_id: &str,
    ) -> WorkOsResult<User, GetUserByExternalIdError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/users/external_id/{external_id}"))?;
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

    use crate::{ApiKey, WorkOs, user_management::UserId};

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
                "/user_management/users/external_id/f1ffa2b2-c20b-4d39-be5c-212726e11222",
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
            .get_user_by_external_id("f1ffa2b2-c20b-4d39-be5c-212726e11222")
            .await
            .unwrap();

        assert_eq!(user.id, UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
    }
}
