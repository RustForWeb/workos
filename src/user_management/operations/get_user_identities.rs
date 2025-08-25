use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{Identity, UserId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetUserIdentities`].
#[derive(Debug, Error)]
pub enum GetUserIdentitiesError {}

impl From<GetUserIdentitiesError> for WorkOsError<GetUserIdentitiesError> {
    fn from(err: GetUserIdentitiesError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get User Identities](https://workos.com/docs/reference/user-management/identity/list)
#[async_trait]
pub trait GetUserIdentities {
    /// Get a list of identities associated with the user.
    ///
    /// [WorkOS Docs: Get User Identities](https://workos.com/docs/reference/user-management/identity/list)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetUserIdentitiesError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let identities = workos
    ///     .user_management()
    ///     .get_user_identities(&UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_user_identities(
        &self,
        user_id: &UserId,
    ) -> WorkOsResult<Vec<Identity>, GetUserIdentitiesError>;
}

#[async_trait]
impl GetUserIdentities for UserManagement<'_> {
    async fn get_user_identities(
        &self,
        user_id: &UserId,
    ) -> WorkOsResult<Vec<Identity>, GetUserIdentitiesError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/users/{user_id}/identities"))?;

        let users = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<Vec<Identity>>()
            .await?;

        Ok(users)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::user_management::{IdentityId, UserId};
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_user_identities_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/user_management/users/user_01E4ZCR3C56J083X43JQXF3JK5/identities",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!([
                    {
                        "idp_id": "4F42ABDE-1E44-4B66-824A-5F733C037A6D",
                        "type": "OAuth",
                        "provider": "MicrosoftOAuth"
                    }
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let list = workos
            .user_management()
            .get_user_identities(&UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"))
            .await
            .unwrap();

        assert_eq!(
            list.into_iter().next().map(|identity| identity.idp_id),
            Some(IdentityId::from("4F42ABDE-1E44-4B66-824A-5F733C037A6D"))
        )
    }
}
