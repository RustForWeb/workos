use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::mfa::{AuthenticationChallenge, AuthenticationChallengeId, Mfa, MfaCode};
use crate::{ResponseExt, WorkOsResult};

/// The response for [`VerifyChallenge`].
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyChallengeResponse {
    /// The relevant Authentication Challenge.
    pub challenge: AuthenticationChallenge,

    /// Indicates whether the code was correct.
    #[serde(rename = "valid")]
    pub is_valid: bool,
}

/// The parameters for [`VerifyChallenge`].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct VerifyChallengeParams<'a> {
    /// The unique ID of the authentication Challenge.
    #[serde(skip)]
    pub authentication_challenge_id: &'a AuthenticationChallengeId,

    /// The 6 digit code to be verified.
    pub code: &'a MfaCode,
}

/// An error returned from [`VerifyChallenge`].
#[derive(Debug, Error)]
pub enum VerifyChallengeError {}

/// [WorkOS Docs: Verify Challenge](https://workos.com/docs/reference/mfa/verify-challenge)
#[async_trait]
pub trait VerifyChallenge {
    /// Verify Authentication Challenge.
    ///
    /// [WorkOS Docs: Verify Challenge](https://workos.com/docs/reference/mfa/verify-challenge)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::mfa::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), VerifyChallengeError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let response = workos
    ///     .mfa()
    ///     .verify_challenge(&VerifyChallengeParams {
    ///         authentication_challenge_id: &AuthenticationChallengeId::from(
    ///             "auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5",
    ///         ),
    ///         code: &MfaCode::from("123456"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn verify_challenge(
        &self,
        params: &VerifyChallengeParams<'_>,
    ) -> WorkOsResult<VerifyChallengeResponse, VerifyChallengeError>;
}

#[async_trait]
impl VerifyChallenge for Mfa<'_> {
    async fn verify_challenge(
        &self,
        params: &VerifyChallengeParams<'_>,
    ) -> WorkOsResult<VerifyChallengeResponse, VerifyChallengeError> {
        let url = self.workos.base_url().join(&format!(
            "/auth/challenges/{id}/verify",
            id = params.authentication_challenge_id
        ))?;
        let verify_response = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<VerifyChallengeResponse>()
            .await?;

        Ok(verify_response)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::mfa::{AuthenticationChallengeId, MfaCode};
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_verify_challenge_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "POST",
                "/auth/challenges/auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5/verify",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body(r#"{"code":"123456"}"#)
            .with_status(201)
            .with_body(
                json!({
                  "challenge": {
                    "object": "authentication_challenge",
                    "id": "auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5",
                    "created_at": "2022-02-15T15:26:53.274Z",
                    "updated_at": "2022-02-15T15:26:53.274Z",
                    "expires_at": "2022-02-15T15:36:53.279Z",
                    "authentication_factor_id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ"
                  },
                  "valid": true
                })
                .to_string(),
            )
            .create_async()
            .await;

        let verify = workos
            .mfa()
            .verify_challenge(&VerifyChallengeParams {
                authentication_challenge_id: &AuthenticationChallengeId::from(
                    "auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5",
                ),
                code: &MfaCode::from("123456"),
            })
            .await
            .unwrap();

        assert_eq!(
            verify.challenge.id,
            AuthenticationChallengeId::from("auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5")
        )
    }
}
