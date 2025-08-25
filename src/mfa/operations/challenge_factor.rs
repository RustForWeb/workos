use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::mfa::{AuthenticationChallenge, AuthenticationFactorId, Mfa};
use crate::{ResponseExt, WorkOsResult};

/// The type of authentication factor to challenge.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ChallengeAuthenticationFactorType<'a> {
    /// Challenge a time-based one-time password (TOTP) factor.
    Totp,

    /// Challenge an SMS authentication factor.
    Sms {
        /// The template for the sent SMS message.
        ///
        /// Use the `{{code}}` token to inject the one-time code into the message, e.g.,
        /// `"Your Foo Corp one-time code is {{code}}."`.
        #[serde(rename = "sms_template", skip_serializing_if = "Option::is_none")]
        template: Option<&'a str>,
    },
}

/// The parameters for [`ChallengeFactor`].
#[derive(Debug, Serialize)]
pub struct ChallengeFactorParams<'a> {
    /// The ID of the authentication factor to challenge.
    #[serde(skip)]
    pub authentication_factor_id: &'a AuthenticationFactorId,

    /// The type of the authentication factor to challenge.
    #[serde(flatten)]
    pub r#type: ChallengeAuthenticationFactorType<'a>,
}

/// An error returned from [`ChallengeFactor`].
#[derive(Debug, Error)]
pub enum ChallengeFactorError {}

/// [WorkOS Docs: Challenge Factor](https://workos.com/docs/reference/mfa/challenge-factor)
#[async_trait]
pub trait ChallengeFactor {
    /// Creates a challenge for an authentication factor.
    ///
    /// [WorkOS Docs: Challenge Factor](https://workos.com/docs/reference/mfa/challenge-factor)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::mfa::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ChallengeFactorError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let challenge = workos
    ///     .mfa()
    ///     .challenge_factor(&ChallengeFactorParams {
    ///         authentication_factor_id: &AuthenticationFactorId::from(
    ///             "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
    ///         ),
    ///         r#type: ChallengeAuthenticationFactorType::Totp,
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn challenge_factor(
        &self,
        params: &ChallengeFactorParams<'_>,
    ) -> WorkOsResult<AuthenticationChallenge, ChallengeFactorError>;
}

#[async_trait]
impl ChallengeFactor for Mfa<'_> {
    async fn challenge_factor(
        &self,
        params: &ChallengeFactorParams<'_>,
    ) -> WorkOsResult<AuthenticationChallenge, ChallengeFactorError> {
        let url = self.workos.base_url().join(&format!(
            "/auth/factors/{id}/challenge",
            id = params.authentication_factor_id
        ))?;
        let challenge = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<AuthenticationChallenge>()
            .await?;

        Ok(challenge)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::mfa::{AuthenticationChallengeId, AuthenticationFactorId};
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_challenge_factor_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "POST",
                "/auth/factors/auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ/challenge",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body("{}")
            .with_status(201)
            .with_body(
                json!({
                  "object": "authentication_challenge",
                  "id": "auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5",
                  "authentication_factor_id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
                  "expires_at": "2022-02-15T15:36:53.279Z",
                  "created_at": "2022-02-15T15:26:53.274Z",
                  "updated_at": "2022-02-15T15:26:53.274Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let challenge = workos
            .mfa()
            .challenge_factor(&ChallengeFactorParams {
                authentication_factor_id: &AuthenticationFactorId::from(
                    "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
                ),
                r#type: ChallengeAuthenticationFactorType::Totp,
            })
            .await
            .unwrap();

        assert_eq!(
            challenge.id,
            AuthenticationChallengeId::from("auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5")
        )
    }

    #[tokio::test]
    async fn it_calls_the_challenge_factor_endpoint_with_an_sms_template() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "POST",
                "/auth/factors/auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ/challenge",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body(r#"{"sms_template":"Here's your one-time code: {{code}}"}"#)
            .with_status(201)
            .with_body(
                json!({
                  "object": "authentication_challenge",
                  "id": "auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5",
                  "authentication_factor_id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
                  "expires_at": "2022-02-15T15:36:53.279Z",
                  "created_at": "2022-02-15T15:26:53.274Z",
                  "updated_at": "2022-02-15T15:26:53.274Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let challenge = workos
            .mfa()
            .challenge_factor(&ChallengeFactorParams {
                authentication_factor_id: &AuthenticationFactorId::from(
                    "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
                ),
                r#type: ChallengeAuthenticationFactorType::Sms {
                    template: Some("Here's your one-time code: {{code}}"),
                },
            })
            .await
            .unwrap();

        assert_eq!(
            challenge.id,
            AuthenticationChallengeId::from("auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5")
        )
    }
}
