use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::user_management::{PasswordReset, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`CreatePasswordReset`].
#[derive(Debug, Serialize)]
pub struct CreatePasswordResetParams<'a> {
    /// The email address of the user.
    pub email: &'a str,
}

/// An error returned from [`CreatePasswordReset`].
#[derive(Debug, Error, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum CreatePasswordResetError {
    /// Entity not found error.
    #[error("entity_not_found: {message}")]
    EntityNotFound {
        /// A human-readable message describing the error.
        message: String,

        /// The entity ID.
        entity_id: String,
    },
}

impl From<CreatePasswordResetError> for WorkOsError<CreatePasswordResetError> {
    fn from(err: CreatePasswordResetError) -> Self {
        Self::Operation(err)
    }
}

#[async_trait]
pub(crate) trait HandleCreatePasswordResetError
where
    Self: Sized,
{
    async fn handle_create_password_reset_error(
        self,
    ) -> WorkOsResult<Self, CreatePasswordResetError>;
}

#[async_trait]
impl HandleCreatePasswordResetError for Response {
    async fn handle_create_password_reset_error(
        self,
    ) -> WorkOsResult<Self, CreatePasswordResetError> {
        match self.error_for_status_ref() {
            Ok(_) => Ok(self),
            Err(err) => match err.status() {
                Some(StatusCode::NOT_FOUND) => {
                    let error = self.json::<CreatePasswordResetError>().await?;

                    Err(WorkOsError::Operation(error))
                }
                _ => Err(WorkOsError::RequestError(err)),
            },
        }
    }
}

/// [WorkOS Docs: Create a password reset token](https://workos.com/docs/reference/user-management/password-reset/create)
#[async_trait]
pub trait CreatePasswordReset {
    /// Creates a one-time token that can be used to reset a user's password.
    ///
    /// [WorkOS Docs: Create a password reset token](https://workos.com/docs/reference/user-management/password-reset/create)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), CreatePasswordResetError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let password_reset = workos
    ///     .user_management()
    ///     .create_password_reset(&CreatePasswordResetParams {
    ///          email: "marcelina@example.com",
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_password_reset(
        &self,
        params: &CreatePasswordResetParams<'_>,
    ) -> WorkOsResult<PasswordReset, CreatePasswordResetError>;
}

#[async_trait]
impl CreatePasswordReset for UserManagement<'_> {
    async fn create_password_reset(
        &self,
        params: &CreatePasswordResetParams<'_>,
    ) -> WorkOsResult<PasswordReset, CreatePasswordResetError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/password_reset")?;
        let user = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_error()?
            .handle_create_password_reset_error()
            .await?
            .json::<PasswordReset>()
            .await?;

        Ok(user)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::user_management::PasswordResetId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_create_password_reset_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/password_reset")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
            .with_body(
                json!({
                    "id": "password_reset_01HYGDNK5G7FZ4YJFXYXPB5JRW",
                    "user_id": "user_01HWWYEH2NPT48X82ZT23K5AX4",
                    "email": "marcelina.davis@example.com",
                    "password_reset_token": "Z1uX3RbwcIl5fIGJJJCXXisdI",
                    "password_reset_url": "https://your-app.com/reset-password?token=Z1uX3RbwcIl5fIGJJJCXXisdI",
                    "expires_at": "2021-07-01T19:07:33.155Z",
                    "created_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let password_reset = workos
            .user_management()
            .create_password_reset(&CreatePasswordResetParams {
                email: "marcelina.davis@example.com",
            })
            .await
            .unwrap();

        assert_eq!(
            password_reset.id,
            PasswordResetId::from("password_reset_01HYGDNK5G7FZ4YJFXYXPB5JRW")
        )
    }
}
