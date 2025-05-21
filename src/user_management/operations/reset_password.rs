use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{PasswordResetToken, User, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`ResetPassword`].
#[derive(Debug, Serialize)]
pub struct ResetPasswordParams<'a> {
    /// The `token` query parameter from the password reset URL.
    pub token: &'a PasswordResetToken,

    /// The new password to set for the user.
    pub new_password: &'a str,
}

/// An error returned from [`ResetPassword`].
#[derive(Debug, Error)]
pub enum ResetPasswordError {}

impl From<ResetPasswordError> for WorkOsError<ResetPasswordError> {
    fn from(err: ResetPasswordError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Reset the password](https://workos.com/docs/reference/user-management/password-reset/reset-password)
#[async_trait]
pub trait ResetPassword {
    /// Sets a new password using the token query parameter from the link that the user received.
    ///
    /// [WorkOS Docs: Reset the password](https://workos.com/docs/reference/user-management/password-reset/reset-password)
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashSet;
    ///
    /// # use workos_sdk::WorkOsResult;
    /// # use workos_sdk::user_management::*;
    /// use workos_sdk::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ResetPasswordError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let user = workos
    ///     .user_management()
    ///     .reset_password(&ResetPasswordParams {
    ///         token: &PasswordResetToken::from("stpIJ48IFJt0HhSIqjf8eppe0"),
    ///         new_password: "i8uv6g34kd490s",
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn reset_password(
        &self,
        params: &ResetPasswordParams<'_>,
    ) -> WorkOsResult<User, ResetPasswordError>;
}

#[async_trait]
impl ResetPassword for UserManagement<'_> {
    async fn reset_password(
        &self,
        params: &ResetPasswordParams<'_>,
    ) -> WorkOsResult<User, ResetPasswordError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/password_reset/confirm")?;

        let user = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()?
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
    async fn it_calls_the_reset_password_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/password_reset/confirm")
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
                    "metadata": {},
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let user = workos
            .user_management()
            .reset_password(&ResetPasswordParams {
                token: &PasswordResetToken::from("stpIJ48IFJt0HhSIqjf8eppe0"),
                new_password: "i8uv6g34kd490s",
            })
            .await
            .unwrap();

        assert_eq!(user.id, UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
    }
}
