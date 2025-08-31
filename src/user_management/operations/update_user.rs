use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{PasswordParams, User, UserId, UserManagement};
use crate::{Metadata, ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`UpdateUser`].
#[derive(Debug, Serialize)]
pub struct UpdateUserParams<'a> {
    /// The ID of the user.
    #[serde(skip_serializing)]
    pub user_id: &'a UserId,

    /// The user's first name.
    pub first_name: Option<&'a str>,

    /// The user's last name.
    pub last_name: Option<&'a str>,

    /// The user's email address.
    pub email: Option<&'a str>,

    /// Whether the user's email address was previously verified.
    pub email_verified: Option<bool>,

    /// The password to set for the user.
    #[serde(flatten)]
    pub password: Option<&'a PasswordParams<'a>>,

    /// The external ID of the user.
    pub external_id: Option<&'a str>,

    /// Object containing metadata key/value pairs associated with the user.
    pub metadata: Option<Metadata>,
}

/// An error returned from [`UpdateUser`].
#[derive(Debug, Error)]
pub enum UpdateUserError {}

impl From<UpdateUserError> for WorkOsError<UpdateUserError> {
    fn from(err: UpdateUserError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Update a user](https://workos.com/docs/reference/user-management/user/update)
#[async_trait]
pub trait UpdateUser {
    /// Updates properties of a user. The omitted properties will be left unchanged.
    ///
    /// [WorkOS Docs: Update a user](https://workos.com/docs/reference/user-management/user/update)
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    ///
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, Metadata, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), UpdateUserError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let user = workos
    ///     .user_management()
    ///     .update_user(&UpdateUserParams {
    ///         user_id: &UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"),
    ///         first_name: Some("Marcelina"),
    ///         last_name: Some("Davis"),
    ///         email: None,
    ///         email_verified: Some(true),
    ///         password: None,
    ///         external_id: Some("2fe01467-f7ea-4dd2-8b79-c2b4f56d0191"),
    ///         metadata: Some(Metadata(HashMap::from([(
    ///             "language".to_string(),
    ///             "en".to_string(),
    ///         )]))),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn update_user(
        &self,
        params: &UpdateUserParams<'_>,
    ) -> WorkOsResult<User, UpdateUserError>;
}

#[async_trait]
impl UpdateUser for UserManagement<'_> {
    async fn update_user(
        &self,
        params: &UpdateUserParams<'_>,
    ) -> WorkOsResult<User, UpdateUserError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/users/{id}", id = params.user_id))?;
        let user = self
            .workos
            .client()
            .put(url)
            .bearer_auth(self.workos.key())
            .json(&params)
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
    use std::collections::HashMap;

    use serde_json::json;
    use tokio;

    use crate::user_management::UserId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_update_user_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "PUT",
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
                    "external_id": "2fe01467-f7ea-4dd2-8b79-c2b4f56d0191",
                    "metadata": {
                        "language": "en"
                    },
                    "last_sign_in_at": "2021-06-25T19:07:33.155Z",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let user = workos
            .user_management()
            .update_user(&UpdateUserParams {
                user_id: &UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"),
                first_name: Some("Marcelina"),
                last_name: Some("Davis"),
                email: None,
                email_verified: Some(true),
                password: None,
                external_id: Some("2fe01467-f7ea-4dd2-8b79-c2b4f56d0191"),
                metadata: Some(Metadata(HashMap::from([(
                    "language".to_string(),
                    "en".to_string(),
                )]))),
            })
            .await
            .unwrap();

        assert_eq!(user.id, UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
    }
}
