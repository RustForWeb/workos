use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{MagicAuth, MagicAuthId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetMagicAuth`].
#[derive(Debug, Error)]
pub enum GetMagicAuthError {}

impl From<GetMagicAuthError> for WorkOsError<GetMagicAuthError> {
    fn from(err: GetMagicAuthError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get a Magic Auth code](https://workos.com/docs/reference/user-management/magic-auth/get)
#[async_trait]
pub trait GetMagicAuth {
    /// Get the details of an existing Magic Auth code that can be used to send an email to a user for authentication.
    ///
    /// [WorkOS Docs: Get a Magic Auth code](https://workos.com/docs/reference/user-management/magic-auth/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetMagicAuthError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let magic_auth = workos
    ///     .user_management()
    ///     .get_magic_auth(&MagicAuthId::from("magic_auth_01E4ZCR3C56J083X43JQXF3JK5"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_magic_auth(&self, id: &MagicAuthId) -> WorkOsResult<MagicAuth, GetMagicAuthError>;
}

#[async_trait]
impl GetMagicAuth for UserManagement<'_> {
    async fn get_magic_auth(&self, id: &MagicAuthId) -> WorkOsResult<MagicAuth, GetMagicAuthError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/magic_auth/{id}"))?;
        let magic_auth = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<MagicAuth>()
            .await?;

        Ok(magic_auth)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_magic_auth_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/user_management/magic_auth/magic_auth_01E4ZCR3C56J083X43JQXF3JK5",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "id": "magic_auth_01E4ZCR3C56J083X43JQXF3JK5",
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

        let magic_auth = workos
            .user_management()
            .get_magic_auth(&MagicAuthId::from("magic_auth_01E4ZCR3C56J083X43JQXF3JK5"))
            .await
            .unwrap();

        assert_eq!(
            magic_auth.id,
            MagicAuthId::from("magic_auth_01E4ZCR3C56J083X43JQXF3JK5")
        )
    }
}
