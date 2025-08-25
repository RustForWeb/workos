use async_trait::async_trait;
use thiserror::Error;

use crate::sso::{Connection, ConnectionId, Sso};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetConnection`].
#[derive(Debug, Error)]
pub enum GetConnectionError {}

impl From<GetConnectionError> for WorkOsError<GetConnectionError> {
    fn from(err: GetConnectionError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get a Connection](https://workos.com/docs/reference/sso/connection/get)
#[async_trait]
pub trait GetConnection {
    /// Retrieves a [`Connection`] by its ID.
    ///
    /// [WorkOS Docs: Get a Connection](https://workos.com/docs/reference/sso/connection/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::sso::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetConnectionError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let connection = workos
    ///     .sso()
    ///     .get_connection(&ConnectionId::from("conn_01E4ZCR3C56J083X43JQXF3JK5"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_connection(
        &self,
        id: &ConnectionId,
    ) -> WorkOsResult<Connection, GetConnectionError>;
}

#[async_trait]
impl GetConnection for Sso<'_> {
    async fn get_connection(
        &self,
        id: &ConnectionId,
    ) -> WorkOsResult<Connection, GetConnectionError> {
        let url = self.workos.base_url().join(&format!("/connections/{id}"))?;
        let connection = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<Connection>()
            .await?;

        Ok(connection)
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
    async fn it_calls_the_get_connection_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/connections/conn_01E4ZCR3C56J083X43JQXF3JK5")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "object": "connection",
                  "id": "conn_01E4ZCR3C56J083X43JQXF3JK5",
                  "organization_id": "org_01EHWNCE74X7JSDV0X3SZ3KJNY",
                  "connection_type": "GoogleOAuth",
                  "name": "Foo Corp",
                  "state": "active",
                  "created_at": "2021-06-25T19:07:33.155Z",
                  "updated_at": "2021-06-25T19:07:33.155Z",
                  "domains": [
                    {
                      "id": "conn_domain_01EHWNFTAFCF3CQAE5A9Q0P1YB",
                      "object": "connection_domain",
                      "domain": "foo-corp.com"
                    }
                  ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let connection = workos
            .sso()
            .get_connection(&ConnectionId::from("conn_01E4ZCR3C56J083X43JQXF3JK5"))
            .await
            .unwrap();

        assert_eq!(
            connection.id,
            ConnectionId::from("conn_01E4ZCR3C56J083X43JQXF3JK5")
        )
    }

    #[tokio::test]
    async fn it_returns_an_error_when_the_get_connection_endpoint_returns_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/connections/conn_01E4ZCR3C56J083X43JQXF3JK5")
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
            .sso()
            .get_connection(&ConnectionId::from("conn_01E4ZCR3C56J083X43JQXF3JK5"))
            .await;

        assert_matches!(result, Err(WorkOsError::Unauthorized))
    }
}
