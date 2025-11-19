use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{Session, UserId, UserManagement};
use crate::{PaginatedList, PaginationParams, ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for the [`ListSessions`] function.
#[derive(Debug, Serialize)]
pub struct ListSessionsParams<'a> {
    /// The ID of the user.
    #[serde(skip_serializing)]
    pub user_id: &'a UserId,

    /// The pagination parameters to use when listing sessions.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,
}

/// An error returned from [`ListSessions`].
#[derive(Debug, Error)]
pub enum ListSessionsError {}

impl From<ListSessionsError> for WorkOsError<ListSessionsError> {
    fn from(err: ListSessionsError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List sessions](https://workos.com/docs/reference/user-management/session/list)
#[async_trait]
pub trait ListSessions {
    /// Get a list of all active sessions for a specific user.
    ///
    /// [WorkOS Docs: List sessions](https://workos.com/docs/reference/user-management/session/list)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    /// use workos::organizations::OrganizationId;
    ///
    /// # async fn run() -> WorkOsResult<(), ListSessionsError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let sessions = workos
    ///     .user_management()
    ///     .list_sessions(&ListSessionsParams {
    ///         user_id: &UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"),
    ///         pagination: Default::default(),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_sessions(
        &self,
        params: &ListSessionsParams,
    ) -> WorkOsResult<PaginatedList<Session>, ListSessionsError>;
}

#[async_trait]
impl ListSessions for UserManagement<'_> {
    async fn list_sessions(
        &self,
        params: &ListSessionsParams,
    ) -> WorkOsResult<PaginatedList<Session>, ListSessionsError> {
        let url = self.workos.base_url().join(&format!(
            "/user_management/users/{}/sessions",
            params.user_id
        ))?;

        let sessions = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<Session>>()
            .await?;

        Ok(sessions)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs, user_management::SessionId};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_list_sessions_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/user_management/users/user_01E4ZCR3C56J083X43JQXF3JK5/sessions")
            .match_query(Matcher::UrlEncoded("order".to_string(), "desc".to_string()))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "data": [
                        {
                            "object": "session",
                            "id": "session_01E4ZCR3C56J083X43JQXF3JK5",
                            "user_id": "user_01E4ZCR3C56J083X43JQXF3JK5",
                            "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                            "status": "active",
                            "auth_method": "password",
                            "ip_address": "192.168.1.1",
                            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                            "expires_at": "2025-07-23T15:00:00.000Z",
                            "ended_at": null,
                            "created_at": "2025-07-23T14:00:00.000Z",
                            "updated_at": "2025-07-23T14:00:00.000Z"
                        }
                    ],
                    "list_metadata": {
                        "before": "session_01E4ZCR3C56J083X43JQXF3JK5",
                        "after": "session_01EJBGJT2PC6638TN5Y380M40Z"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .user_management()
            .list_sessions(&ListSessionsParams {
                user_id: &UserId::from("user_01E4ZCR3C56J083X43JQXF3JK5"),
                pagination: Default::default(),
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list
                .data
                .into_iter()
                .next()
                .map(|session| session.id),
            Some(SessionId::from("session_01E4ZCR3C56J083X43JQXF3JK5"))
        )
    }
}
