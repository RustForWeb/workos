use async_trait::async_trait;
use serde::Serialize;

use crate::passwordless::{Passwordless, PasswordlessSessionId};
use crate::{ResponseExt, WorkOsResult};

/// The parameters for [`SendPasswordlessSession`].
#[derive(Debug, Serialize)]
pub struct SendPasswordlessSessionParams<'a> {
    /// The ID of the passwordless session to send an email for.
    pub id: &'a PasswordlessSessionId,
}

/// An error returned from [`SendPasswordlessSession`].
#[derive(Debug)]
pub enum SendPasswordlessSessionError {}

/// [WorkOS Docs: Send a Passwordless Session](https://workos.com/docs/reference/magic-link/passwordless-session/send-email)
#[async_trait]
pub trait SendPasswordlessSession {
    /// Sends a [`PasswordlessSession`](crate::passwordless::PasswordlessSession).
    ///
    /// [WorkOS Docs: Send a Passwordless Session](https://workos.com/docs/reference/magic-link/passwordless-session/send-email)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::passwordless::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), SendPasswordlessSessionError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// workos
    ///     .passwordless()
    ///     .send_passwordless_session(&SendPasswordlessSessionParams {
    ///         id: &PasswordlessSessionId::from("passwordless_session_01EHDAK2BFGWCSZXP9HGZ3VK8C"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn send_passwordless_session(
        &self,
        params: &SendPasswordlessSessionParams<'_>,
    ) -> WorkOsResult<(), SendPasswordlessSessionError>;
}

#[async_trait]
impl SendPasswordlessSession for Passwordless<'_> {
    async fn send_passwordless_session(
        &self,
        params: &SendPasswordlessSessionParams<'_>,
    ) -> WorkOsResult<(), SendPasswordlessSessionError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/passwordless/sessions/{id}/send", id = params.id))?;
        self.workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use matches::assert_matches;
    use serde_json::json;
    use tokio;

    use crate::passwordless::PasswordlessSessionId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_send_passwordless_session_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "POST",
                "/passwordless/sessions/passwordless_session_01EG1BHJMVYMFBQYZTTC0N73CR/send",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
            .with_body(json!({ "success": true}).to_string())
            .create_async()
            .await;

        let result = workos
            .passwordless()
            .send_passwordless_session(&SendPasswordlessSessionParams {
                id: &PasswordlessSessionId::from("passwordless_session_01EG1BHJMVYMFBQYZTTC0N73CR"),
            })
            .await;

        assert_matches!(result, Ok(()))
    }
}
