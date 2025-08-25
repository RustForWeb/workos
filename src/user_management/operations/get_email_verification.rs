use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{EmailVerification, EmailVerificationId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetEmailVerification`].
#[derive(Debug, Error)]
pub enum GetEmailVerificationError {}

impl From<GetEmailVerificationError> for WorkOsError<GetEmailVerificationError> {
    fn from(err: GetEmailVerificationError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get an email verification code](https://workos.com/docs/reference/user-management/email-verification/get)
#[async_trait]
pub trait GetEmailVerification {
    /// Get the details of an existing email verification code that can be used to send an email to a user for verification.
    ///
    /// [WorkOS Docs: Get an email verification code](https://workos.com/docs/reference/user-management/email-verification/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetEmailVerificationError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization = workos
    ///     .user_management()
    ///     .get_email_verification(&EmailVerificationId::from("email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_email_verification(
        &self,
        id: &EmailVerificationId,
    ) -> WorkOsResult<EmailVerification, GetEmailVerificationError>;
}

#[async_trait]
impl GetEmailVerification for UserManagement<'_> {
    async fn get_email_verification(
        &self,
        id: &EmailVerificationId,
    ) -> WorkOsResult<EmailVerification, GetEmailVerificationError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/email_verification/{id}"))?;
        let organization = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<EmailVerification>()
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
    async fn it_calls_the_get_email_verification_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/user_management/email_verification/email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "id": "email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3",
                    "user_id": "user_01HWWYEH2NPT48X82ZT23K5AX4",
                    "email": "marcelina.davis@example.com",
                    "expires_at": "2021-07-01T19:07:33.155Z",
                    "code": "123456",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization = workos
            .user_management()
            .get_email_verification(&EmailVerificationId::from(
                "email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3",
            ))
            .await
            .unwrap();

        assert_eq!(
            organization.id,
            EmailVerificationId::from("email_verification_01HYGGEB6FYMWQNWF3XDZG7VV3")
        )
    }
}
