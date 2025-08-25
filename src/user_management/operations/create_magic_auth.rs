use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{MagicAuth, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`CreateMagicAuth`].
#[derive(Debug, Serialize)]
pub struct CreateMagicAuthParams<'a> {
    /// The email address of the user.
    pub email: &'a str,

    /// The token of an invitation.
    pub invitation_token: Option<&'a str>,
}

/// An error returned from [`CreateMagicAuth`].
#[derive(Debug, Error)]
pub enum CreateMagicAuthError {}

impl From<CreateMagicAuthError> for WorkOsError<CreateMagicAuthError> {
    fn from(err: CreateMagicAuthError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Create a Magic Auth code](https://workos.com/docs/reference/user-management/magic-auth/create)
#[async_trait]
pub trait CreateMagicAuth {
    /// Creates a one-time authentication code that can be sent to the user's email address.
    ///
    /// [WorkOS Docs: Create a Magic Auth code](https://workos.com/docs/reference/user-management/magic-auth/create)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), CreateMagicAuthError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let magic_auth = workos
    ///     .user_management()
    ///     .create_magic_auth(&CreateMagicAuthParams {
    ///          email: "marcelina@example.com",
    ///          invitation_token: None,
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_magic_auth(
        &self,
        params: &CreateMagicAuthParams<'_>,
    ) -> WorkOsResult<MagicAuth, CreateMagicAuthError>;
}

#[async_trait]
impl CreateMagicAuth for UserManagement<'_> {
    async fn create_magic_auth(
        &self,
        params: &CreateMagicAuthParams<'_>,
    ) -> WorkOsResult<MagicAuth, CreateMagicAuthError> {
        let url = self.workos.base_url().join("/user_management/magic_auth")?;
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
            .json::<MagicAuth>()
            .await?;

        Ok(user)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::user_management::MagicAuthId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_create_magic_auth_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/magic_auth")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
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
            .create_magic_auth(&CreateMagicAuthParams {
                email: "marcelina@example.com",
                invitation_token: None,
            })
            .await
            .unwrap();

        assert_eq!(
            magic_auth.id,
            MagicAuthId::from("magic_auth_01E4ZCR3C56J083X43JQXF3JK5")
        )
    }
}
