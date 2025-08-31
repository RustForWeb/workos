use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;

use crate::{
    WorkOsError, WorkOsResult, mfa::AuthenticationFactorIdAndType,
    organizations::OrganizationIdAndName, sso::ConnectionId,
};

use super::{AuthenticateMethods, EmailVerificationId, PendingAuthenticationToken, User};

/// Whether an error is an unauthorized error.
pub trait IsUnauthorized {
    /// Whether an error is an unauthorized error.
    fn is_unauthorized(&self) -> bool;
}

/// An error returned from authenticate requests.
#[derive(Debug, Deserialize, Error)]
#[error(transparent)]
#[serde(untagged)]
pub enum AuthenticateError {
    /// Error tagged with a `code` field.
    WithCode(AuthenticateErrorWithCode),

    /// Error tagged with an `error` field.
    WithError(AuthenticateErrorWithError),
}

impl IsUnauthorized for AuthenticateError {
    fn is_unauthorized(&self) -> bool {
        match &self {
            AuthenticateError::WithError(AuthenticateErrorWithError::Other { error, .. }) => {
                matches!(error.as_str(), "invalid_client" | "unauthorized_client")
            }
            _ => false,
        }
    }
}

/// An error returned from authenticate requests tagged with a `code` field.
#[derive(Debug, Deserialize, Error)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AuthenticateErrorWithCode {
    /// Email verification required error.
    ///
    /// This error indicates that a user with an unverified email address attempted to authenticate in an environment where email verification is required.
    /// It includes a pending authentication token that should be used to complete the authentication.
    #[error("email_verification_required: {message}")]
    EmailVerificationRequired {
        /// A human-readable message describing the error.
        message: String,

        /// A token that should be used to complete the authentication with a corresponding method after this error occurs.
        pending_authentication_token: PendingAuthenticationToken,

        ///The email address of the user.
        email: String,

        /// The unique ID of the email verification code.
        email_verification_id: EmailVerificationId,
    },

    /// Invalid credentials error.
    #[error("invalid_credentials: {message}")]
    InvalidCredentials {
        /// A human-readable message describing the error.
        message: String,
    },

    /// Invalid one-time code error.
    #[error("invalid_one_time_code: {message}")]
    InvalidOneTimeCode {
        /// A human-readable message describing the error.
        message: String,
    },

    /// Invalid pending authentication token error.
    #[error("invalid_pending_authentication_token: {message}")]
    InvalidPendingAuthenticationToken {
        /// A human-readable message describing the error.
        message: String,
    },

    /// MFA enrollment error
    ///
    /// This error indicates that a user who is not enrolled into MFA attempted to authenticate in an environment where MFA is required.
    /// It includes a pending authentication token that should be used to authenticate the user once they enroll into MFA.
    #[error("mfa_enrollment: {message}")]
    MfaEnrollment {
        /// A human-readable message describing the error.
        message: String,

        /// A token that should be used to complete the authentication with a corresponding method after this error occurs.
        pending_authentication_token: PendingAuthenticationToken,

        /// The corresponding user object.
        user: Box<User>,
    },

    /// MFA challenge error
    ///
    /// This error indicates that a user enrolled into MFA attempted to authenticate in an environment where MFA is required.
    /// It includes a pending authentication token and a list of factors that the user is enrolled in that should be used to complete the authentication.
    #[error("mfa_challenge: {message}")]
    MfaChallenge {
        /// A human-readable message describing the error.
        message: String,

        /// A token that should be used to complete the authentication with a corresponding method after this error occurs.
        pending_authentication_token: PendingAuthenticationToken,

        /// IDs and types of the factors the user is enrolled in.
        authentication_factors: Vec<AuthenticationFactorIdAndType>,

        /// The corresponding user object.
        user: Box<User>,
    },

    /// One-time code expired error
    #[error("one_time_code_expired: {message}")]
    OneTimeCodeExpired {
        /// A human-readable message describing the error.
        message: String,
    },

    /// One-time code too many attempts error
    #[error("one_time_code_too_many_attempts: {message}")]
    OneTimeCodeTooManyAttempts {
        /// A human-readable message describing the error.
        message: String,
    },

    /// Organization selection required error
    ///
    /// This error indicates that the user is a member of multiple organizations and must select which organization to sign in to.
    /// It includes a list of organizations the user is a member of and a pending authentication token that should be used to complete the authentication.
    #[error("organization_selection_required: {message}")]
    OrganizationSelectionRequired {
        /// A human-readable message describing the error.
        message: String,

        /// A token that should be used to complete the authentication with a corresponding method after this error occurs.
        pending_authentication_token: PendingAuthenticationToken,

        /// The corresponding user object.
        user: Box<User>,

        /// IDs and names of the organizations the user is a member of.
        organizations: Vec<OrganizationIdAndName>,
    },

    /// Other error.
    #[error("{code}: {message}")]
    #[serde(untagged)]
    Other {
        /// A string constant that distinguishes the error type.
        code: String,

        /// A human-readable message describing the error.
        message: String,
    },
}

impl AuthenticateErrorWithCode {
    /// The string constant that distinguishes the error type.
    pub fn code(&self) -> &str {
        match self {
            AuthenticateErrorWithCode::EmailVerificationRequired { .. } => {
                "email_verification_requried"
            }
            AuthenticateErrorWithCode::InvalidCredentials { .. } => "invalid_credentials",
            AuthenticateErrorWithCode::InvalidOneTimeCode { .. } => "invalid_one_time_code",
            AuthenticateErrorWithCode::InvalidPendingAuthenticationToken { .. } => {
                "invalid_pending_authentication_token"
            }
            AuthenticateErrorWithCode::MfaEnrollment { .. } => "mfa_enrollment",
            AuthenticateErrorWithCode::MfaChallenge { .. } => "mfa_challenge",
            AuthenticateErrorWithCode::OneTimeCodeExpired { .. } => "one_time_code_expired",
            AuthenticateErrorWithCode::OneTimeCodeTooManyAttempts { .. } => {
                "one_time_code_too_many_attempts"
            }
            AuthenticateErrorWithCode::OrganizationSelectionRequired { .. } => {
                "organization_selection_required"
            }
            AuthenticateErrorWithCode::Other { code, .. } => code,
        }
    }

    /// The human-readable message describing the error.
    pub fn message(&self) -> &str {
        match self {
            AuthenticateErrorWithCode::EmailVerificationRequired { message, .. } => message,
            AuthenticateErrorWithCode::InvalidCredentials { message } => message,
            AuthenticateErrorWithCode::InvalidOneTimeCode { message } => message,
            AuthenticateErrorWithCode::InvalidPendingAuthenticationToken { message } => message,
            AuthenticateErrorWithCode::MfaEnrollment { message, .. } => message,
            AuthenticateErrorWithCode::MfaChallenge { message, .. } => message,
            AuthenticateErrorWithCode::OneTimeCodeExpired { message } => message,
            AuthenticateErrorWithCode::OneTimeCodeTooManyAttempts { message } => message,
            AuthenticateErrorWithCode::OrganizationSelectionRequired { message, .. } => message,
            AuthenticateErrorWithCode::Other { message, .. } => message,
        }
    }
}

/// An error returned from authenticate requests tagged by an `error` field.
#[derive(Debug, Deserialize, Error)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AuthenticateErrorWithError {
    /// SSO required error
    ///
    /// This error indicates that a user attempted to authenticate into an organization that requires SSO using a different authentication method.
    /// It includes a list of SSO connections that may be used to complete the authentication.
    #[error("sso_required: {error_description}")]
    SsoRequired {
        /// A human-readable message describing the error.
        error_description: String,

        /// The email of the authenticating user.
        email: String,

        /// A list of SSO connection IDs that the user is required to authenticate with. One of these connections must be used.
        sso_connection_ids: Vec<ConnectionId>,

        /// A token that should be used to complete the authentication with the authorization_code grant type after this error occurs.
        /// This may be null, which indicates that no pending authentication token needs to be passed to the authenticate call.
        pending_authentication_token: Option<PendingAuthenticationToken>,
    },

    /// Organization authentication required error
    ///
    /// This error indicates that a user attempted to authenticate with an authentication method that is not allowed by the organization that has a domain policy managing this user.
    /// It includes all the possible methods the user can use to authenticate.
    #[error("organization_authentication_methods_required: {error_description}")]
    OrganizationAuthenticationMethodsRequired {
        /// A human-readable message describing the error.
        error_description: String,

        /// The email of the authenticating user.
        email: String,

        /// A list of SSO connection IDs that the user is required to authenticate with. One of these connections must be used.
        sso_connection_ids: Vec<ConnectionId>,

        /// Possible methods the user can use to authenticate.
        authenticate_methods: AuthenticateMethods,
    },

    /// Other error.
    #[error("{error}: {error_description}")]
    #[serde(untagged)]
    Other {
        /// A string constant that distinguishes the error type.
        error: String,

        /// A human-readable message describing the error.
        error_description: String,
    },
}

impl AuthenticateErrorWithError {
    /// The string constant that distinguishes the error type.
    pub fn error(&self) -> &str {
        match self {
            AuthenticateErrorWithError::SsoRequired { .. } => "sso_required",
            AuthenticateErrorWithError::OrganizationAuthenticationMethodsRequired { .. } => {
                "organization_authentication_methods_required"
            }
            AuthenticateErrorWithError::Other { error, .. } => error,
        }
    }

    /// The human-readable message describing the error.
    pub fn error_description(&self) -> &str {
        match self {
            AuthenticateErrorWithError::SsoRequired {
                error_description, ..
            } => error_description,
            AuthenticateErrorWithError::OrganizationAuthenticationMethodsRequired {
                error_description,
                ..
            } => error_description,
            AuthenticateErrorWithError::Other {
                error_description, ..
            } => error_description,
        }
    }
}

#[async_trait]
pub(crate) trait HandleAuthenticateError<E>
where
    Self: Sized,
    E: DeserializeOwned + IsUnauthorized,
{
    async fn handle_authenticate_error(self) -> WorkOsResult<Self, E>;
}

#[async_trait]
impl<E> HandleAuthenticateError<E> for Response
where
    E: DeserializeOwned + IsUnauthorized,
{
    async fn handle_authenticate_error(self) -> WorkOsResult<Self, E> {
        match self.error_for_status_ref() {
            Ok(_) => Ok(self),
            Err(err) => match err.status() {
                Some(StatusCode::BAD_REQUEST) => {
                    let authenticate_error = self.json::<E>().await?;

                    Err(if authenticate_error.is_unauthorized() {
                        WorkOsError::Unauthorized
                    } else {
                        WorkOsError::Operation(authenticate_error)
                    })
                }
                Some(StatusCode::FORBIDDEN) => {
                    let authenticate_error = self.json::<E>().await?;

                    Err(if authenticate_error.is_unauthorized() {
                        WorkOsError::Unauthorized
                    } else {
                        WorkOsError::Operation(authenticate_error)
                    })
                }
                _ => Err(WorkOsError::RequestError(err)),
            },
        }
    }
}
