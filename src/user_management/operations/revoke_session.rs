use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{SessionId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`RevokeSession`].
#[derive(Debug, Serialize)]
pub struct RevokeSessionParams<'a> {
    /// The ID of the session.
    pub session_id: &'a SessionId,
}

/// An error returned from [`RevokeSession`].
#[derive(Debug, Error)]
pub enum RevokeSessionError {}

impl From<RevokeSessionError> for WorkOsError<RevokeSessionError> {
    fn from(err: RevokeSessionError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Revoke session](https://workos.com/docs/reference/user-management/session/revoke)
#[async_trait]
pub trait RevokeSession {
    /// Revoke a session.
    ///
    /// [WorkOS Docs: Revoke session](https://workos.com/docs/reference/user-management/session/revoke)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, Metadata, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), RevokeSessionError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// workos
    ///     .user_management()
    ///     .revoke_session(&RevokeSessionParams {
    ///         session_id: &SessionId::from("session_01E4ZCR3C56J083X43JQXF3JK5"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn revoke_session(
        &self,
        params: &RevokeSessionParams<'_>,
    ) -> WorkOsResult<(), RevokeSessionError>;
}

#[async_trait]
impl RevokeSession for UserManagement<'_> {
    async fn revoke_session(
        &self,
        params: &RevokeSessionParams<'_>,
    ) -> WorkOsResult<(), RevokeSessionError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/sessions/revoke")?;

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

    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_revoke_session_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/sessions/revoke")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body(r#"{"session_id":"session_01E4ZCR3C56J083X43JQXF3JK5"}"#)
            .with_status(202)
            .create_async()
            .await;

        let result = workos
            .user_management()
            .revoke_session(&RevokeSessionParams {
                session_id: &SessionId::from("session_01E4ZCR3C56J083X43JQXF3JK5"),
            })
            .await;

        assert_matches!(result, Ok(()));
    }
}
