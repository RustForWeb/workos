use async_trait::async_trait;
use serde::Serialize;

use crate::directory_sync::{Directory, DirectorySync};
use crate::organizations::OrganizationId;
use crate::{PaginatedList, PaginationParams, ResponseExt, WorkOsResult};

/// The parameters for [`ListDirectories`].
#[derive(Debug, Default, Serialize)]
pub struct ListDirectoriesParams<'a> {
    /// The pagination parameters to use when listing directories.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,

    /// Searchable text to match against Directory names.
    pub search: Option<&'a String>,

    /// Filter Directories by their associated organization.
    pub organization_id: Option<&'a OrganizationId>,
}

/// [WorkOS Docs: List Directories](https://workos.com/docs/reference/directory-sync/directory/list)
#[async_trait]
pub trait ListDirectories {
    /// Get a list of all of your existing directories matching the criteria specified.
    ///
    /// [WorkOS Docs: List Directories](https://workos.com/docs/reference/directory-sync/directory/list)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::directory_sync::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ()> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let paginated_directories = workos
    ///     .directory_sync()
    ///     .list_directories(&ListDirectoriesParams {
    ///         ..Default::default()
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_directories(
        &self,
        params: &ListDirectoriesParams<'_>,
    ) -> WorkOsResult<PaginatedList<Directory>, ()>;
}

#[async_trait]
impl ListDirectories for DirectorySync<'_> {
    async fn list_directories(
        &self,
        params: &ListDirectoriesParams<'_>,
    ) -> WorkOsResult<PaginatedList<Directory>, ()> {
        let url = self.workos.base_url().join("/directories")?;
        let directories = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<Directory>>()
            .await?;

        Ok(directories)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_list_directories_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/directories")
            .match_query(Matcher::UrlEncoded("order".to_string(), "desc".to_string()))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "data": [{
                        "id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                        "domain": "foo-corp.com",
                        "name": "Foo Corp",
                        "organization_id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                        "object": "directory",
                        "state": "unlinked",
                        "type": "gsuite directory",
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:08:33.155Z"
                    },
                    {
                        "id": "directory_01E8CS3GSBEBZ1F1CZAEE3KHDG",
                        "domain": "foo-corp.com",
                        "external_key": "r3NDlInUnAe6i4wG",
                        "name": "Foo Corp",
                        "organization_id": "org_01EHZNVPK3SFK441A1RGBFPANT",
                        "object": "directory",
                        "state": "linked",
                        "type": "okta scim v2.0",
                        "created_at": "2021-06-25T19:09:33.155Z",
                        "updated_at": "2021-06-25T19:10:33.155Z"
                    }],
                    "list_metadata" : {
                        "after" : "directory_01E1JJS84MFPPQ3G655FHTKX6Z",
                        "before" : "directory_01E1JJS84MFPPQ3G655FHTKX6Z"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .directory_sync()
            .list_directories(&Default::default())
            .await
            .unwrap();

        assert_eq!(
            paginated_list.metadata.after,
            Some("directory_01E1JJS84MFPPQ3G655FHTKX6Z".to_string())
        )
    }
}
