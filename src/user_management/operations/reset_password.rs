use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use serde::{Deserialize, Serialize};
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

/// The response for [`ResetPassword`].
#[derive(Debug, Deserialize)]
pub struct ResetPasswordResponse {
    /// The corresponding user object.
    pub user: User,
}

/// An error returned from [`ResetPassword`].
#[derive(Debug, Error, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ResetPasswordError {
    /// Password reset token not found error.
    #[error("password_reset_token_not_found: {message}")]
    PasswordResetTokenNotFound {
        /// A human-readable message describing the error.
        message: String,
    },

    /// Password reset error.
    #[error("password_reset_error: {message}")]
    PasswordResetError {
        /// A human-readable message describing the error.
        message: String,

        /// List of errors.
        errors: Vec<PasswordResetError>,
    },
}

impl From<ResetPasswordError> for WorkOsError<ResetPasswordError> {
    fn from(err: ResetPasswordError) -> Self {
        Self::Operation(err)
    }
}

/// Password reset error.
#[derive(Debug, Error, Deserialize, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum PasswordResetError {
    /// Password reset token expired error.
    #[error("password_reset_token_expired: {message}")]
    PasswordResetTokenExpired {
        /// A human-readable message describing the error.
        message: String,
    },

    /// Password too weak error.
    #[error("password_too_weak: {message}")]
    PasswordTooWeak {
        /// A human-readable message describing the error.
        message: String,

        /// Human-readable suggestions.
        suggestions: Vec<String>,

        /// A human-readable warning.
        warning: String,
    },
}

#[async_trait]
pub(crate) trait HandleResetPasswordError
where
    Self: Sized,
{
    async fn handle_reset_password_error(self) -> WorkOsResult<Self, ResetPasswordError>;
}

#[async_trait]
impl HandleResetPasswordError for Response {
    async fn handle_reset_password_error(self) -> WorkOsResult<Self, ResetPasswordError> {
        match self.error_for_status_ref() {
            Ok(_) => Ok(self),
            Err(err) => match err.status() {
                Some(StatusCode::BAD_REQUEST) | Some(StatusCode::NOT_FOUND) => {
                    let error = self.json::<ResetPasswordError>().await?;

                    Err(WorkOsError::Operation(error))
                }
                _ => Err(WorkOsError::RequestError(err)),
            },
        }
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
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ResetPasswordError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let response = workos
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
    ) -> WorkOsResult<ResetPasswordResponse, ResetPasswordError>;
}

#[async_trait]
impl ResetPassword for UserManagement<'_> {
    async fn reset_password(
        &self,
        params: &ResetPasswordParams<'_>,
    ) -> WorkOsResult<ResetPasswordResponse, ResetPasswordError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/password_reset/confirm")?;

        let response = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_error()?
            .handle_reset_password_error()
            .await?
            .json::<ResetPasswordResponse>()
            .await?;

        Ok(response)
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
                    "user": {
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
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let response = workos
            .user_management()
            .reset_password(&ResetPasswordParams {
                token: &PasswordResetToken::from("stpIJ48IFJt0HhSIqjf8eppe0"),
                new_password: "i8uv6g34kd490s",
            })
            .await
            .unwrap();

        assert_eq!(
            response.user.id,
            UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5")
        )
    }
}
