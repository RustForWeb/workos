use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::mfa::AuthenticationFactor;
use crate::user_management::{UserId, UserManagement};
use crate::{PaginatedList, PaginationParams, ResponseExt, WorkOsError, WorkOsResult};

/// Parameters for the [`ListAuthFactors`] function.
#[derive(Debug, Serialize)]
pub struct ListAuthFactorsParams<'a> {
    /// The user ID to list the authentication factors for.
    #[serde(skip)]
    pub id: &'a UserId,

    /// The pagination parameters to use when listing authentication factors.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,
}

/// An error returned from [`ListAuthFactors`].
#[derive(Debug, Error)]
pub enum ListAuthFactorsError {}

impl From<ListAuthFactorsError> for WorkOsError<ListAuthFactorsError> {
    fn from(err: ListAuthFactorsError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List authentication factors](https://workos.com/docs/reference/user-management/mfa/list-auth-factors)
#[async_trait]
pub trait ListAuthFactors {
    /// Lists the authentication factors for a user.
    ///
    /// [WorkOS Docs: List authentication factors](https://workos.com/docs/reference/user-management/mfa/list-auth-factors)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ()> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let paginated_auth_factors = workos
    ///     .user_management()
    ///     .list_auth_factors(&ListAuthFactorsParams {
    ///         id: &UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"),
    ///         pagination: Default::default(),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_auth_factors(
        &self,
        params: &ListAuthFactorsParams<'_>,
    ) -> WorkOsResult<PaginatedList<AuthenticationFactor>, ()>;
}

#[async_trait]
impl ListAuthFactors for UserManagement<'_> {
    async fn list_auth_factors(
        &self,
        params: &ListAuthFactorsParams<'_>,
    ) -> WorkOsResult<PaginatedList<AuthenticationFactor>, ()> {
        let url = self.workos.base_url().join(&format!(
            "/user_management/users/{}/auth_factors",
            params.id
        ))?;

        let auth_factors = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<AuthenticationFactor>>()
            .await?;

        Ok(auth_factors)
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
    async fn it_calls_the_list_auth_factors_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/users/user_01FVYZ5QM8N98T9ME5BCB2BBMJ/auth_factors")
            .match_query(Matcher::UrlEncoded("order".to_string(), "desc".to_string()))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
                        "object": "authentication_factor",
                        "id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
                        "created_at": "2022-02-15T15:14:19.392Z",
                        "updated_at": "2022-02-15T15:14:19.392Z",
                        "type": "totp",
                        "totp": {
                            "issuer": "Foo Corp",
                            "user": "alan.turing@example.com",
                            "qr_code": "data:image/png;base64,{base64EncodedPng}",
                            "secret": "NAGCCFS3EYRB422HNAKAKY3XDUORMSRF",
                            "uri": "otpauth://totp/FooCorp:alan.turing@example.com?secret=NAGCCFS3EYRB422HNAKAKY3XDUORMSRF&issuer=FooCorp"
                        },
                        "userId": "user_01FVYZ5QM8N98T9ME5BCB2BBMJ"
                    }
                  ],
                  "list_metadata": {
                    "before": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
                    "after": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_auth_factors(&ListAuthFactorsParams {
                id: &UserId::from("user_01FVYZ5QM8N98T9ME5BCB2BBMJ"),
                pagination: Default::default(),
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.metadata.after,
            Some("auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ".to_string())
        )
    }
}
