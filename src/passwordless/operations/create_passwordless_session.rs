use async_trait::async_trait;
use serde::Serialize;

use crate::passwordless::{Passwordless, PasswordlessSession};
use crate::{ResponseExt, WorkOsResult};

/// The type of passwordless session to create.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CreatePasswordlessSessionType<'a> {
    /// Create a Magic Link session.
    #[serde(rename = "MagicLink")]
    MagicLink {
        /// The email of the user to send a Magic Link to.
        email: &'a str,
    },
}

/// The parameters for [`CreatePasswordlessSession`].
#[derive(Debug, Serialize)]
pub struct CreatePasswordlessSessionParams<'a> {
    /// The type of passwordless session to create.
    #[serde(flatten)]
    pub r#type: CreatePasswordlessSessionType<'a>,

    /// The redirect URI the user will be redirected to after successfully signing in.
    ///
    /// If not provided this will be the default redirect URI set in the WorkOS Dashboard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<&'a str>,

    /// The state parameter that will be passed back to the redirect URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<&'a str>,
}

/// An error returned from [`CreatePasswordlessSession`].
#[derive(Debug)]
pub enum CreatePasswordlessSessionError {}

/// [WorkOS Docs: Create a Passwordless Session](https://workos.com/docs/reference/magic-link/passwordless-session/create-session)
#[async_trait]
pub trait CreatePasswordlessSession {
    /// Creates a [`PasswordlessSession`].
    ///
    /// [WorkOS Docs: Create a Passwordless Session](https://workos.com/docs/reference/magic-link/passwordless-session/create-session)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::passwordless::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), CreatePasswordlessSessionError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let passwordless_session = workos
    ///     .passwordless()
    ///     .create_passwordless_session(&CreatePasswordlessSessionParams {
    ///         r#type: CreatePasswordlessSessionType::MagicLink {
    ///             email: "marcelina@foo-corp.com",
    ///         },
    ///         redirect_uri: None,
    ///         state: None,
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn create_passwordless_session(
        &self,
        params: &CreatePasswordlessSessionParams<'_>,
    ) -> WorkOsResult<PasswordlessSession, CreatePasswordlessSessionError>;
}

#[async_trait]
impl CreatePasswordlessSession for Passwordless<'_> {
    async fn create_passwordless_session(
        &self,
        params: &CreatePasswordlessSessionParams<'_>,
    ) -> WorkOsResult<PasswordlessSession, CreatePasswordlessSessionError> {
        let url = self.workos.base_url().join("/passwordless/sessions")?;
        let passwordless_session = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PasswordlessSession>()
            .await?;

        Ok(passwordless_session)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::passwordless::PasswordlessSessionId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_create_passwordless_session_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/passwordless/sessions")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body(r#"{"type":"MagicLink","email":"marcelina@foo-corp.com"}"#)
            .with_status(201)
            .with_body(
                json!({
                    "object": "passwordless_session",
                    "id": "passwordless_session_01EHDAK2BFGWCSZXP9HGZ3VK8C",
                    "email": "marcelina@foo-corp.com",
                    "expires_at": "2020-08-13T05:50:00.000Z",
                    "link": "https://auth.workos.com/passwordless/token/confirm",
                })
                .to_string(),
            )
            .create_async()
            .await;

        let passwordless_session = workos
            .passwordless()
            .create_passwordless_session(&CreatePasswordlessSessionParams {
                r#type: CreatePasswordlessSessionType::MagicLink {
                    email: "marcelina@foo-corp.com",
                },
                redirect_uri: None,
                state: None,
            })
            .await
            .unwrap();

        assert_eq!(
            passwordless_session.id,
            PasswordlessSessionId::from("passwordless_session_01EHDAK2BFGWCSZXP9HGZ3VK8C")
        )
    }
}
