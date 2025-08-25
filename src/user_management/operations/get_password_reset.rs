use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{PasswordReset, PasswordResetId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetPasswordReset`].
#[derive(Debug, Error)]
pub enum GetPasswordResetError {}

impl From<GetPasswordResetError> for WorkOsError<GetPasswordResetError> {
    fn from(err: GetPasswordResetError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get a password reset token](https://workos.com/docs/reference/user-management/password-reset/get)
#[async_trait]
pub trait GetPasswordReset {
    /// Get the details of an existing password reset token that can be used to reset a user's password.
    ///
    /// [WorkOS Docs: Get a password reset token](https://workos.com/docs/reference/user-management/password-reset/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetPasswordResetError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let password_reset = workos
    ///     .user_management()
    ///     .get_password_reset(&PasswordResetId::from("password_reset_01E4ZCR3C56J083X43JQXF3JK5"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_password_reset(
        &self,
        id: &PasswordResetId,
    ) -> WorkOsResult<PasswordReset, GetPasswordResetError>;
}

#[async_trait]
impl GetPasswordReset for UserManagement<'_> {
    async fn get_password_reset(
        &self,
        id: &PasswordResetId,
    ) -> WorkOsResult<PasswordReset, GetPasswordResetError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/password_reset/{id}"))?;
        let organization = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PasswordReset>()
            .await?;

        Ok(organization)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_password_reset_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/user_management/password_reset/password_reset_01HYGDNK5G7FZ4YJFXYXPB5JRW",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
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

        let organization = workos
            .user_management()
            .get_password_reset(&PasswordResetId::from(
                "password_reset_01HYGDNK5G7FZ4YJFXYXPB5JRW",
            ))
            .await
            .unwrap();

        assert_eq!(
            organization.id,
            PasswordResetId::from("password_reset_01HYGDNK5G7FZ4YJFXYXPB5JRW")
        )
    }
}
