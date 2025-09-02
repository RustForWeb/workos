use async_trait::async_trait;
use thiserror::Error;

use crate::mfa::{AuthenticationFactorId, Mfa};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`DeleteFactor`].
#[derive(Debug, Error)]
pub enum DeleteFactorError {}

impl From<DeleteFactorError> for WorkOsError<DeleteFactorError> {
    fn from(err: DeleteFactorError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Delete Factor](https://workos.com/docs/reference/mfa/delete-factor)
#[async_trait]
pub trait DeleteFactor {
    /// Permanently deletes an Authentication Factor. It cannot be undone.
    ///
    /// [WorkOS Docs: Delete Factor](https://workos.com/docs/reference/mfa/delete-factor)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::mfa::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), DeleteFactorError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// workos
    ///     .mfa()
    ///     .delete_factor(&AuthenticationFactorId::from("auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn delete_factor(
        &self,
        organization_id: &AuthenticationFactorId,
    ) -> WorkOsResult<(), DeleteFactorError>;
}

#[async_trait]
impl DeleteFactor for Mfa<'_> {
    async fn delete_factor(
        &self,
        authentication_factor_id: &AuthenticationFactorId,
    ) -> WorkOsResult<(), DeleteFactorError> {
        let url = self
            .workos
            .base_url()
            .join(&format!("/auth/factors/{authentication_factor_id}"))?;

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
    async fn it_calls_the_delete_factor_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "DELETE",
                "/auth/factors/auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(202)
            .create_async()
            .await;

        let result = workos
            .mfa()
            .delete_factor(&AuthenticationFactorId::from(
                "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
            ))
            .await;

        assert_matches!(result, Ok(()));
    }
}
