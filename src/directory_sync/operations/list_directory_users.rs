use async_trait::async_trait;
use serde::Serialize;

use crate::directory_sync::{DirectoryGroupId, DirectoryId, DirectorySync, DirectoryUser};
use crate::{PaginatedList, PaginationParams, ResponseExt, WorkOsResult};

/// A filter for [`ListDirectoryUsers`].
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum DirectoryUsersFilter<'a> {
    /// Retrieve directory users within the specified directory.
    Directory {
        /// The ID of the directory to retrieve directory users in.
        directory: &'a DirectoryId,
    },

    /// Retrieve directory users within the specified directory group.
    Group {
        /// The ID of the directory group to retrieve directory users in.
        group: &'a DirectoryGroupId,
    },
}

/// The parameters for [`ListDirectoryUsers`].
#[derive(Debug, Serialize)]
pub struct ListDirectoryUsersParams<'a> {
    /// The pagination parameters to use when listing directory users.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,

    /// The filter to use when listing directory users.
    #[serde(flatten)]
    pub filter: DirectoryUsersFilter<'a>,
}

/// [WorkOS Docs: List Directory Users](https://workos.com/docs/reference/directory-sync/user/list)
#[async_trait]
pub trait ListDirectoryUsers {
    /// Retrieves a list of [`DirectoryUser`]s.
    ///
    /// [WorkOS Docs: List Directory Users](https://workos.com/docs/reference/directory-sync/user/list)
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::directory_sync::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ()> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let paginated_users = workos
    ///     .directory_sync()
    ///     .list_directory_users(&ListDirectoryUsersParams {
    ///         filter: DirectoryUsersFilter::Directory {
    ///             directory: &DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74"),
    ///         },
    ///         pagination: Default::default(),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_directory_users(
        &self,
        params: &ListDirectoryUsersParams<'_>,
    ) -> WorkOsResult<PaginatedList<DirectoryUser>, ()>;
}

#[async_trait]
impl ListDirectoryUsers for DirectorySync<'_> {
    async fn list_directory_users(
        &self,
        params: &ListDirectoryUsersParams<'_>,
    ) -> WorkOsResult<PaginatedList<DirectoryUser>, ()> {
        let url = self.workos.base_url().join("/directory_users")?;
        let directory_users = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<DirectoryUser>>()
            .await?;

        Ok(directory_users)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::directory_sync::DirectoryUserId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_list_directory_users_endpoint_with_a_directory_id() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/directory_users")
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
                  "data": [
                    {
                      "id": "directory_user_01E1JJHG3BFJ3FNRRHSFWEBNCS",
                      "idp_id": "1902",
                      "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                      "emails": [
                        {
                          "primary": true,
                          "type": "work",
                          "value": "jan@foo-corp.com"
                        }
                      ],
                      "first_name": "Jan",
                      "last_name": "Brown",
                      "username": "jan@foo-corp.com",
                      "groups": [
                        {
                          "id": "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
                          "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                          "name": "Engineering",
                          "created_at": "2021-06-25T19:07:33.155Z",
                          "updated_at": "2021-06-25T19:07:33.155Z",
                          "raw_attributes": {}
                        }
                      ],
                      "state": "active",
                      "created_at": "2021-06-25T19:07:33.155Z",
                      "updated_at": "2021-06-25T19:07:33.155Z",
                      "custom_attributes": {
                        "department": "Engineering"
                      },
                      "raw_attributes": {}
                    },
                    {
                      "id": "directory_user_01E1JJHG10ANRA2V6PAX3GD7TE",
                      "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                      "idp_id": "8953",
                      "emails": [
                        {
                          "primary": true,
                          "type": "work",
                          "value": "rosalinda@foo-corp.com"
                        }
                      ],
                      "first_name": "Rosalinda",
                      "last_name": "Swift",
                      "username": "rosalinda@foo-corp.com",
                      "groups": [
                        {
                          "id": "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
                          "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                          "name": "Engineering",
                          "created_at": "2021-06-25T19:07:33.155Z",
                          "updated_at": "2021-06-25T19:07:33.155Z",
                          "raw_attributes": {}
                        }
                      ],
                      "state": "active",
                      "created_at": "2021-06-25T19:07:33.155Z",
                      "updated_at": "2021-06-25T19:07:33.155Z",
                      "custom_attributes": {
                        "department": "Engineering"
                      },
                      "raw_attributes": {}
                    }
                  ],
                  "object": "list",
                  "list_metadata": {
                    "after": "directory_user_01E4RH82CC8QAP8JTRCTNDSS4C",
                    "before": "directory_user_01E4RH828021B9ZZB8KH8E2Z1W"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .directory_sync()
            .list_directory_users(&ListDirectoryUsersParams {
                pagination: Default::default(),
                filter: DirectoryUsersFilter::Directory {
                    directory: &DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74"),
                },
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list
                .data
                .into_iter()
                .next()
                .map(|directory_user| directory_user.id),
            Some(DirectoryUserId::from(
                "directory_user_01E1JJHG3BFJ3FNRRHSFWEBNCS"
            ))
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_directory_users_endpoint_with_a_directory_group_id() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/directory_users")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".to_string(), "desc".to_string()),
                Matcher::UrlEncoded(
                    "group".to_string(),
                    "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT".to_string(),
                ),
            ]))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
                      "id": "directory_user_01E1JJHG3BFJ3FNRRHSFWEBNCS",
                      "idp_id": "1902",
                      "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                      "emails": [
                        {
                          "primary": true,
                          "type": "work",
                          "value": "jan@foo-corp.com"
                        }
                      ],
                      "first_name": "Jan",
                      "last_name": "Brown",
                      "username": "jan@foo-corp.com",
                      "groups": [
                        {
                          "id": "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
                          "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                          "name": "Engineering",
                          "created_at": "2021-06-25T19:07:33.155Z",
                          "updated_at": "2021-06-25T19:07:33.155Z",
                          "raw_attributes": {}
                        }
                      ],
                      "state": "active",
                      "created_at": "2021-06-25T19:07:33.155Z",
                      "updated_at": "2021-06-25T19:07:33.155Z",
                      "custom_attributes": {
                        "department": "Engineering"
                      },
                      "raw_attributes": {}
                    },
                    {
                      "id": "directory_user_01E1JJHG10ANRA2V6PAX3GD7TE",
                      "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                      "idp_id": "8953",
                      "emails": [
                        {
                          "primary": true,
                          "type": "work",
                          "value": "rosalinda@foo-corp.com"
                        }
                      ],
                      "first_name": "Rosalinda",
                      "last_name": "Swift",
                      "username": "rosalinda@foo-corp.com",
                      "groups": [
                        {
                          "id": "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
                          "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                          "name": "Engineering",
                          "created_at": "2021-06-25T19:07:33.155Z",
                          "updated_at": "2021-06-25T19:07:33.155Z",
                          "raw_attributes": {}
                        }
                      ],
                      "state": "active",
                      "created_at": "2021-06-25T19:07:33.155Z",
                      "updated_at": "2021-06-25T19:07:33.155Z",
                      "custom_attributes": {
                        "department": "Engineering"
                      },
                      "raw_attributes": {}
                    }
                  ],
                  "object": "list",
                  "list_metadata": {
                    "after": "directory_user_01E4RH82CC8QAP8JTRCTNDSS4C",
                    "before": "directory_user_01E4RH828021B9ZZB8KH8E2Z1W"
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .directory_sync()
            .list_directory_users(&ListDirectoryUsersParams {
                pagination: Default::default(),
                filter: DirectoryUsersFilter::Group {
                    group: &DirectoryGroupId::from("directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT"),
                },
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list
                .data
                .into_iter()
                .next()
                .map(|directory_user| directory_user.id),
            Some(DirectoryUserId::from(
                "directory_user_01E1JJHG3BFJ3FNRRHSFWEBNCS"
            ))
        )
    }
}
