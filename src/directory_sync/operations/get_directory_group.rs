use async_trait::async_trait;
use thiserror::Error;

use crate::directory_sync::{DirectoryGroup, DirectoryGroupId, DirectorySync};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetDirectoryGroup`].
#[derive(Debug, Error)]
pub enum GetDirectoryGroupError {}

impl From<GetDirectoryGroupError> for WorkOsError<GetDirectoryGroupError> {
    fn from(err: GetDirectoryGroupError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get a Directory Group](https://workos.com/docs/reference/directory-sync/group/get)
#[async_trait]
pub trait GetDirectoryGroup {
    /// Retrieves a [`DirectoryGroup`] by its ID.
    ///
    /// [WorkOS Docs: Get a Directory Group](https://workos.com/docs/reference/directory-sync/group/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::directory_sync::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetDirectoryGroupError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let directory_group = workos
    ///     .directory_sync()
    ///     .get_directory_group(&DirectoryGroupId::from(
    ///         "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
    ///     ))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_directory_group(
        &self,
        id: &DirectoryGroupId,
    ) -> WorkOsResult<DirectoryGroup, GetDirectoryGroupError>;
}

#[async_trait]
impl GetDirectoryGroup for DirectorySync<'_> {
    async fn get_directory_group(
        &self,
        id: &DirectoryGroupId,
    ) -> WorkOsResult<DirectoryGroup, GetDirectoryGroupError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/directory_groups/{id}"))?;
        let directory_group = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<DirectoryGroup>()
            .await?;

        Ok(directory_group)
    }
}

#[cfg(test)]
mod test {
    use matches::assert_matches;
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_directory_group_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server.mock(
            "GET",
            "/directory_groups/directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
        )
        .match_header("Authorization", "Bearer sk_example_123456789")
        .with_status(200)
        .with_body(
            json!({
              "id" : "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
              "idp_id": "02grqrue4294w24",
              "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
              "name" : "Developers",
              "created_at": "2021-06-25T19:07:33.155Z",
              "updated_at": "2021-06-25T19:07:33.155Z",
              "raw_attributes": {"directory_group_id" : "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT"}
            })
            .to_string(),
        )
        .create_async().await;

        let directory = workos
            .directory_sync()
            .get_directory_group(&DirectoryGroupId::from(
                "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
            ))
            .await
            .unwrap();

        assert_eq!(
            directory.id,
            DirectoryGroupId::from("directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT")
        )
    }

    #[tokio::test]
    async fn it_returns_an_error_when_the_get_directory_group_endpoint_returns_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/directory_groups/directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(401)
            .with_body(
                json!({
                    "message": "Unauthorized"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let result = workos
            .directory_sync()
            .get_directory_group(&DirectoryGroupId::from(
                "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
            ))
            .await;

        assert_matches!(result, Err(WorkOsError::Unauthorized))
    }
}
