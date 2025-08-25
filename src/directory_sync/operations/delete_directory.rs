use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::directory_sync::{DirectoryId, DirectorySync};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`DeleteDirectory`].
#[derive(Debug, Serialize)]
pub struct DeleteDirectoryParams<'a> {
    /// The ID of the directory to delete.
    pub directory_id: &'a DirectoryId,
}

/// An error returned from [`DeleteDirectory`].
#[derive(Debug, Error)]
pub enum DeleteDirectoryError {}

impl From<DeleteDirectoryError> for WorkOsError<DeleteDirectoryError> {
    fn from(err: DeleteDirectoryError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Delete a Directory](https://workos.com/docs/reference/directory-sync/directory/delete)
#[async_trait]
pub trait DeleteDirectory {
    /// Deletes a [`Directory`](crate::directory_sync::Directory).
    ///
    /// [WorkOS Docs: Delete a Directory](https://workos.com/docs/reference/directory-sync/directory/delete)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::directory_sync::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), DeleteDirectoryError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// workos
    ///     .directory_sync()
    ///     .delete_directory(&DeleteDirectoryParams {
    ///         directory_id: &DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete_directory(
        &self,
        params: &DeleteDirectoryParams<'_>,
    ) -> WorkOsResult<(), DeleteDirectoryError>;
}

#[async_trait]
impl DeleteDirectory for DirectorySync<'_> {
    async fn delete_directory(
        &self,
        params: &DeleteDirectoryParams<'_>,
    ) -> WorkOsResult<(), DeleteDirectoryError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/directories/{id}", id = params.directory_id))?;
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

    use crate::directory_sync::DirectoryId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_delete_directory_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "DELETE",
                "/directories/directory_01ECAZ4NV9QMV47GW873HDCX74",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(202)
            .create_async()
            .await;

        let result = workos
            .directory_sync()
            .delete_directory(&DeleteDirectoryParams {
                directory_id: &DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74"),
            })
            .await;

        assert_matches!(result, Ok(()));
    }
}
