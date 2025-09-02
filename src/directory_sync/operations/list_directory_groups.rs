use async_trait::async_trait;
use serde::Serialize;

use crate::directory_sync::{DirectoryGroup, DirectoryId, DirectorySync, DirectoryUserId};
use crate::{PaginatedList, PaginationParams, ResponseExt, WorkOsResult};

/// The parameters for [`ListDirectoryGroups`].
#[derive(Debug, Serialize)]
pub struct ListDirectoryGroupsParams<'a> {
    /// The pagination parameters to use when listing directory groups.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,

    /// Unique identifier of the WorkOS Directory.
    pub directory: Option<&'a DirectoryId>,

    /// Unique identifier of the WorkOS Directory User.
    pub user: Option<&'a DirectoryUserId>,
}

/// [WorkOS Docs: List Directory Groups](https://workos.com/docs/reference/directory-sync/group/list)
#[async_trait]
pub trait ListDirectoryGroups {
    /// Get a list of all of existing directory groups matching the criteria specified.
    ///
    /// [WorkOS Docs: List Directory Groups](https://workos.com/docs/reference/directory-sync/group/list)
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::directory_sync::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ()> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let paginated_groups = workos
    ///     .directory_sync()
    ///     .list_directory_groups(&ListDirectoryGroupsParams {
    ///         directory: Some(&DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74")),
    ///         user: None,
    ///         pagination: Default::default(),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_directory_groups(
        &self,
        params: &ListDirectoryGroupsParams<'_>,
    ) -> WorkOsResult<PaginatedList<DirectoryGroup>, ()>;
}

#[async_trait]
impl ListDirectoryGroups for DirectorySync<'_> {
    async fn list_directory_groups(
        &self,
        params: &ListDirectoryGroupsParams<'_>,
    ) -> WorkOsResult<PaginatedList<DirectoryGroup>, ()> {
        let url = self.workos.base_url().join("/directory_groups")?;
        let directory_groups = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<DirectoryGroup>>()
            .await?;

        Ok(directory_groups)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::directory_sync::DirectoryGroupId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_list_directory_groups_endpoint_with_a_directory_id() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/directory_groups")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".to_string(), "desc".to_string()),
                Matcher::UrlEncoded(
                    "directory".to_string(),
                    "directory_01ECAZ4NV9QMV47GW873HDCX74".to_string(),
                ),
            ]))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "data" : [{
                        "id" : "directory_group_01E1JJS84MFPPQ3G655FHTKX6Z",
                        "idp_id": "02grqrue4294w24",
                        "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                        "organization_id": "org_01EZTR6WYX1A0DSE2CYMGXQ24Y",
                        "name" : "Developers",
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    }],
                    "list_metadata" : {
                        "after" : "directory_group_01E1JJS84MFPPQ3G655FHTKX6Z",
                        "before" : "directory_group_01E1JJS84MFPPQ3G655FHTKX6Z"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .directory_sync()
            .list_directory_groups(&ListDirectoryGroupsParams {
                pagination: Default::default(),
                directory: Some(&DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74")),
                user: None,
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list
                .data
                .into_iter()
                .next()
                .map(|directory_group| directory_group.id),
            Some(DirectoryGroupId::from(
                "directory_group_01E1JJS84MFPPQ3G655FHTKX6Z"
            ))
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_directory_groups_endpoint_with_a_directory_user_id() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/directory_groups")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".to_string(), "desc".to_string()),
                Matcher::UrlEncoded(
                    "user".to_string(),
                    "directory_user_01FYVX377G1S69ASY580WK6WVN".to_string(),
                ),
            ]))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "data": [
                        {
                            "object": "directory_group",
                            "id": "directory_group_01FYVX39X7A7YS95CEAJ9AJT18",
                            "idp_id": "Developers",
                            "directory_id": "directory_01FYVWZ2KGW7KPKGR58VHW1KT2",
                            "name": "Developers",
                            "created_at": "2022-03-23T17:27:24.838Z",
                            "updated_at": "2022-03-23T17:27:24.838Z",
                            "raw_attributes": {
                                "meta": {
                                    "resourceType": "Group"
                                },
                                "members": [],
                                "schemas": [
                                    "urn:ietf:params:scim:schemas:core:2.0:Group"
                                ],
                                "externalId": "0b797e61-352a-4e94-b21b-2be370ec5541",
                                "displayName": "Developers"
                            }
                        }
                    ],
                    "list_metadata": {
                        "before": "directory_group_01FYVX39X7A7YS95CEAJ9AJT18",
                        "after": null
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .directory_sync()
            .list_directory_groups(&ListDirectoryGroupsParams {
                pagination: Default::default(),
                directory: None,
                user: Some(&DirectoryUserId::from(
                    "directory_user_01FYVX377G1S69ASY580WK6WVN",
                )),
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list
                .data
                .into_iter()
                .next()
                .map(|directory_group| directory_group.id),
            Some(DirectoryGroupId::from(
                "directory_group_01FYVX39X7A7YS95CEAJ9AJT18"
            ))
        )
    }
}
