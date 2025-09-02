use async_trait::async_trait;
use thiserror::Error;

use crate::sso::{ConnectionId, Sso};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`DeleteConnection`].
#[derive(Debug, Error)]
pub enum DeleteConnectionError {}

impl From<DeleteConnectionError> for WorkOsError<DeleteConnectionError> {
    fn from(err: DeleteConnectionError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Delete a Connection](https://workos.com/docs/reference/sso/connection/delete)
#[async_trait]
pub trait DeleteConnection {
    /// Deletes a [`Connection`](crate::sso::Connection).
    ///
    /// [WorkOS Docs: Delete a Connection](https://workos.com/docs/reference/sso/connection/delete)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::sso::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), DeleteConnectionError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// workos
    ///     .sso()
    ///     .delete_connection(&ConnectionId::from("conn_01E2NPPCT7XQ2MVVYDHWGK1WN4"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> WorkOsResult<(), DeleteConnectionError>;
}

#[async_trait]
impl DeleteConnection for Sso<'_> {
    async fn delete_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> WorkOsResult<(), DeleteConnectionError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/connections/{connection_id}"))?;

        self.workos
            .client()
            .delete(url)
            .bearer_auth(self.workos.key())
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

    use crate::sso::ConnectionId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_delete_connection_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("DELETE", "/connections/conn_01E2NPPCT7XQ2MVVYDHWGK1WN4")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(202)
            .create_async()
            .await;

        let result = workos
            .sso()
            .delete_connection(&ConnectionId::from("conn_01E2NPPCT7XQ2MVVYDHWGK1WN4"))
            .await;

        assert_matches!(result, Ok(()));
    }
}
