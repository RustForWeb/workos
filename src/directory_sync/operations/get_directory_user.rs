use async_trait::async_trait;
use thiserror::Error;

use crate::directory_sync::{DirectorySync, DirectoryUser, DirectoryUserId};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetDirectoryUser`].
#[derive(Debug, Error)]
pub enum GetDirectoryUserError {}

impl From<GetDirectoryUserError> for WorkOsError<GetDirectoryUserError> {
    fn from(err: GetDirectoryUserError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get a Directory User](https://workos.com/docs/reference/directory-sync/user/get)
#[async_trait]
pub trait GetDirectoryUser {
    /// Get the details of an existing Directory User.
    ///
    /// [WorkOS Docs: Get a Directory User](https://workos.com/docs/reference/directory-sync/user/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::directory_sync::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetDirectoryUserError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let directory_user = workos
    ///     .directory_sync()
    ///     .get_directory_user(&DirectoryUserId::from(
    ///         "directory_user_01E64QS50EAY48S0XJ1AA4WX4D",
    ///     ))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_directory_user(
        &self,
        id: &DirectoryUserId,
    ) -> WorkOsResult<DirectoryUser, GetDirectoryUserError>;
}

#[async_trait]
impl GetDirectoryUser for DirectorySync<'_> {
    async fn get_directory_user(
        &self,
        id: &DirectoryUserId,
    ) -> WorkOsResult<DirectoryUser, GetDirectoryUserError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/directory_users/{id}"))?;
        let directory_user = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<DirectoryUser>()
            .await?;

        Ok(directory_user)
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
    async fn it_calls_the_get_directory_user_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/directory_users/directory_user_01E1JG7J09H96KYP8HM9B0G5SJ",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "id": "directory_user_01E1JG7J09H96KYP8HM9B0G5SJ",
                    "idp_id": "2836",
                    "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                    "organization_id": "org_01EZTR6WYX1A0DSE2CYMGXQ24Y",
                    "first_name": "Marcelina",
                    "last_name": "Davis",
                    "emails": [{
                        "primary": true,
                        "type": "work",
                        "value": "marcelina@foo-corp.com"
                    }],
                    "groups": [{
                        "id": "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
                        "idp_id": "",
                        "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                        "name": "Engineering",
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    }],
                    "state": "active",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z",
                    "custom_attributes": {
                        "department": "Engineering",
                        "job_title": "Software Engineer"
                    },
                    "role": {
                        "slug": "member"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let directory_user = workos
            .directory_sync()
            .get_directory_user(&DirectoryUserId::from(
                "directory_user_01E1JG7J09H96KYP8HM9B0G5SJ",
            ))
            .await
            .unwrap();

        assert_eq!(
            directory_user.id,
            DirectoryUserId::from("directory_user_01E1JG7J09H96KYP8HM9B0G5SJ")
        )
    }

    #[tokio::test]
    async fn it_returns_an_error_when_the_get_directory_user_endpoint_returns_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/directory_users/")
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
            .get_directory_user(&DirectoryUserId::from(""))
            .await;

        assert_matches!(result, Err(WorkOsError::Unauthorized))
    }
}
