use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{UserId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`DeleteUser`].
#[derive(Debug, Serialize)]
pub struct DeleteUserParams<'a> {
    /// The unique ID of the user.
    pub user_id: &'a UserId,
}

/// An error returned from [`DeleteUser`].
#[derive(Debug, Error)]
pub enum DeleteUserError {}

impl From<DeleteUserError> for WorkOsError<DeleteUserError> {
    fn from(err: DeleteUserError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Delete a user](https://workos.com/docs/reference/user-management/user/delete)
#[async_trait]
pub trait DeleteUser {
    /// Permanently deletes a user in the current environment. It cannot be undone.
    ///
    /// [WorkOS Docs: Delete a user](https://workos.com/docs/reference/user-management/user/delete)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), DeleteUserError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// workos
    ///     .user_management()
    ///     .delete_user(&DeleteUserParams {
    ///         user_id: &UserId::from("user_01F3GZ5ZGZBZVQGZVHJFVXZJGZ"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete_user(&self, params: &DeleteUserParams<'_>)
    -> WorkOsResult<(), DeleteUserError>;
}

#[async_trait]
impl DeleteUser for UserManagement<'_> {
    async fn delete_user(
        &self,
        params: &DeleteUserParams<'_>,
    ) -> WorkOsResult<(), DeleteUserError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/users/{id}", id = params.user_id))?;
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
    use tokio;

    use super::*;
    use crate::{ApiKey, WorkOs};
    use matches::assert_matches;

    #[tokio::test]
    async fn it_calls_the_delete_user_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "DELETE",
                "/user_management/users/user_01F3GZ5ZGZBZVQGZVHJFVXZJGZ",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(202)
            .create_async()
            .await;

        let result = workos
            .user_management()
            .delete_user(&DeleteUserParams {
                user_id: &UserId::from("user_01F3GZ5ZGZBZVQGZVHJFVXZJGZ"),
            })
            .await;

        assert_matches!(result, Ok(()));
    }
}
