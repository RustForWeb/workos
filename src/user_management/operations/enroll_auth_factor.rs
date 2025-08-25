use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::mfa::{AuthenticationChallenge, AuthenticationFactor};
use crate::user_management::{UserId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`EnrollAuthFactor`].
#[derive(Debug, Serialize)]
pub struct EnrollAuthFactorParams<'a> {
    /// The unique ID of the user to enroll the auth factor.
    #[serde(skip_serializing)]
    pub user_id: &'a UserId,

    /// The type of the factor to enroll.
    #[serde(flatten)]
    pub r#type: &'a EnrollAuthFactorType<'a>,
}

/// The type of the factor to enroll.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EnrollAuthFactorType<'a> {
    /// Time-based one-time password (TOTP) factor.
    Totp {
        /// Your application or company name displayed in the user's authenticator app.
        ///
        /// Defaults to your WorkOS team name.
        #[serde(rename = "totp_issuer")]
        issuer: Option<&'a str>,

        /// The user's account name displayed in their authenticator app.
        ///
        /// Defaults to the user's email.
        #[serde(rename = "totp_user")]
        user: Option<&'a str>,

        /// The base32-encoded shared secret for TOTP factors.
        ///
        /// This can be provided when creating the auth factor, otherwise it will be generated.
        /// The algorithm used to derive TOTP codes is sha1, the code length is 6 digits,
        /// and the timestep is 30 seconds - the secret must be compatible with these parameters.
        #[serde(rename = "totp_secret")]
        secret: Option<&'a str>,
    },
}

/// The response for [`EnrollAuthFactor`].
#[derive(Debug, Deserialize)]
pub struct EnrollAuthFactorResponse {
    /// The authentication challenge object that is used to complete the authentication process.
    pub authentication_challenge: AuthenticationChallenge,

    /// The authentication factor object that represents the additional authentication method used on top of the existing authentication strategy.
    pub authentication_factor: AuthenticationFactor,
}

/// An error returned from [`EnrollAuthFactor`].
#[derive(Debug, Error, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum EnrollAuthFactorError {}

impl From<EnrollAuthFactorError> for WorkOsError<EnrollAuthFactorError> {
    fn from(err: EnrollAuthFactorError) -> Self {
        Self::Operation(err)
    }
}

#[async_trait]
pub(crate) trait HandleEnrollAuthFactorError
where
    Self: Sized,
{
    async fn handle_enroll_auth_factor_error(self) -> WorkOsResult<Self, EnrollAuthFactorError>;
}

#[async_trait]
impl HandleEnrollAuthFactorError for Response {
    async fn handle_enroll_auth_factor_error(self) -> WorkOsResult<Self, EnrollAuthFactorError> {
        match self.error_for_status_ref() {
            Ok(_) => Ok(self),
            Err(err) => match err.status() {
                Some(StatusCode::BAD_REQUEST) | Some(StatusCode::UNPROCESSABLE_ENTITY) => {
                    // let error = self.json::<EnrollAuthFactorError>().await?;
                    let error = self.json::<serde_json::Value>().await?;

                    println!("{error:#?}");

                    // Err(WorkOsError::Operation(error))
                    Err(WorkOsError::RequestError(err))
                }
                _ => Err(WorkOsError::RequestError(err)),
            },
        }
    }
}

/// [WorkOS Docs: Enroll an authentication factor](https://workos.com/docs/reference/user-management/mfa/enroll-auth-factor)
#[async_trait]
pub trait EnrollAuthFactor {
    /// Enrolls a user in a new authentication factor.
    ///
    /// [WorkOS Docs: Enroll an authentication factor](https://workos.com/docs/reference/user-management/mfa/enroll-auth-factor)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), EnrollAuthFactorError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let response = workos
    ///     .user_management()
    ///     .enroll_auth_factor(&EnrollAuthFactorParams {
    ///         user_id: &UserId::from("user_01FVYZ5QM8N98T9ME5BCB2BBMJ"),
    ///         r#type: &EnrollAuthFactorType::Totp {
    ///             issuer: Some("Foo Corp"),
    ///             user: Some("alan.turing@example.com"),
    ///             secret: None,
    ///         },
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn enroll_auth_factor(
        &self,
        params: &EnrollAuthFactorParams<'_>,
    ) -> WorkOsResult<EnrollAuthFactorResponse, EnrollAuthFactorError>;
}

#[async_trait]
impl EnrollAuthFactor for UserManagement<'_> {
    async fn enroll_auth_factor(
        &self,
        params: &EnrollAuthFactorParams<'_>,
    ) -> WorkOsResult<EnrollAuthFactorResponse, EnrollAuthFactorError> {
        let url = self.workos.base_url().join(&format!(
            "/user_management/users/{}/auth_factors",
            params.user_id
        ))?;

        let response = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_error()?
            .handle_enroll_auth_factor_error()
            .await?
            .json::<EnrollAuthFactorResponse>()
            .await?;

        Ok(response)
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
    async fn it_calls_the_enroll_auth_factor_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/users/user_01FVYZ5QM8N98T9ME5BCB2BBMJ/auth_factors")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(201)
            .with_body(
                json!({
                    "authentication_challenge": {
                        "object": "authentication_challenge",
                        "id": "auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5",
                        "created_at": "2022-02-15T15:26:53.274Z",
                        "updated_at": "2022-02-15T15:26:53.274Z",
                        "expires_at": "2022-02-15T15:36:53.279Z",
                        "authentication_factor_id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ"
                    },
                    "authentication_factor": {
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
                        "user_id": "user_01FVYZ5QM8N98T9ME5BCB2BBMJ"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let response = workos
            .user_management()
            .enroll_auth_factor(&EnrollAuthFactorParams {
                user_id: &UserId::from("user_01FVYZ5QM8N98T9ME5BCB2BBMJ"),
                r#type: &EnrollAuthFactorType::Totp {
                    issuer: Some("Foo Corp"),
                    user: Some("alan.turing@example.com"),
                    secret: None,
                },
            })
            .await
            .unwrap();

        assert_eq!(
            response.authentication_challenge.id,
            AuthenticationChallengeId::from("auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5")
        );
        assert_eq!(
            response.authentication_factor.id,
            AuthenticationFactorId::from("auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ")
        );
    }
}
