use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{PasswordParams, User, UserManagement};
use crate::{Metadata, ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`CreateUser`].
#[derive(Debug, Serialize)]
pub struct CreateUserParams<'a> {
    /// The email address of the user.
    pub email: &'a str,

    /// The password to set for the user.
    #[serde(flatten)]
    pub password: Option<&'a PasswordParams<'a>>,

    /// The first name of the user.
    pub first_name: Option<&'a str>,

    /// The last name of the user.
    pub last_name: Option<&'a str>,

    /// Whether the user's email address was previously verified.
    pub email_verified: Option<bool>,

    /// The external ID of the user.
    pub external_id: Option<&'a str>,

    /// Object containing metadata key/value pairs associated with the user.
    pub metadata: Option<Metadata>,
}

/// An error returned from [`CreateUser`].
#[derive(Debug, Error)]
pub enum CreateUserError {}

impl From<CreateUserError> for WorkOsError<CreateUserError> {
    fn from(err: CreateUserError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Create an User](https://workos.com/docs/reference/user-management/user/create)
#[async_trait]
pub trait CreateUser {
    /// Create a new user in the current environment.
    ///
    /// [WorkOS Docs: Create an User](https://workos.com/docs/reference/user-management/user/create)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), CreateUserError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let user = workos
    ///     .user_management()
    ///     .create_user(&CreateUserParams {
    ///          email: "marcelina@example.com",
    ///          password: Some(&PasswordParams::Password {
    ///              password: "i8uv6g34kd490s",
    ///          }),
    ///          first_name: Some("Marcelina"),
    ///          last_name: Some("Davis"),
    ///          email_verified: Some(false),
    ///          external_id: None,
    ///          metadata: None,
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_user(
        &self,
        params: &CreateUserParams<'_>,
    ) -> WorkOsResult<User, CreateUserError>;
}

#[async_trait]
impl CreateUser for UserManagement<'_> {
    async fn create_user(
        &self,
        params: &CreateUserParams<'_>,
    ) -> WorkOsResult<User, CreateUserError> {
        let url = self.workos.base_url().join("/user_management/users")?;
        let user = self
            .workos
            .client()
            .post(url)
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
    use serde_json::json;
    use tokio;

    use crate::user_management::UserId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_create_user_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/users")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
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
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let user = workos
            .user_management()
            .create_user(&CreateUserParams {
                email: "marcelina@example.com",
                password: Some(&PasswordParams::Password {
                    password: "i8uv6g34kd490s",
                }),
                first_name: Some("Marcelina"),
                last_name: Some("Davis"),
                email_verified: Some(false),
                external_id: None,
                metadata: None,
            })
            .await
            .unwrap();

        assert_eq!(user.id, UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
    }
}
