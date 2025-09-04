use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use base64::{DecodeError, Engine, prelude::BASE64_STANDARD};
use jsonwebtoken::{DecodingKey, Header, Validation, decode, decode_header, jwk::JwkSet};
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    organizations::OrganizationId,
    user_management::{
        AccessTokenClaims, AuthenticatieWithSessionCookieFailureReason,
        AuthenticatieWithSessionCookieFailureResponse, AuthenticatieWithSessionCookieResponse,
        AuthenticatieWithSessionCookieSuccessResponse, GetLogoutUrl, GetLogoutUrlParams,
        SessionCookieData, UserManagement,
    },
};

/// The options for [`CookieSession::refresh`].
#[derive(Debug)]
pub struct RefreshOptions<'a> {
    /// The password with which to encrypt the new session.
    ///
    /// Only pass this in if you want to set a new password separate from the one provided in [`UserManagement::load_sealed_session`].
    pub cookie_password: Option<&'a str>,

    /// The organization ID to use for the new session cookie. Use this if you want to switch organizations.
    pub organization_id: Option<&'a OrganizationId>,
}

/// The options for [`CookieSession::get_logout_url`].
#[derive(Debug)]
pub struct GetLogoutUrlOptions<'a> {
    /// The location the user's browser should be redirected to by the WorkOS API after the session has been ended.
    pub return_to: Option<&'a Url>,
}

/// An error returned from [`CookieSession::get_logout_url`].
#[derive(Debug, Error)]
pub enum GetLogoutUrlError {
    /// Authenticate error.
    #[error("failed to extract session ID for logout URL: {0}")]
    Authenticate(AuthenticatieWithSessionCookieFailureReason),

    /// URL error.
    #[error(transparent)]
    Url(#[from] ParseError),
}

/// TODO
pub struct CookieSession<'a> {
    user_management: &'a UserManagement<'a>,
    cookie_password: &'a str,
    session_data: &'a str,
    client_id: &'a str,

    jwks: JwkSet,
}

impl<'a> CookieSession<'a> {
    pub(crate) fn new(
        user_management: &'a UserManagement,
        client_id: &'a str,
        session_data: &'a str,
        cookie_password: &'a str,
    ) -> Self {
        Self {
            user_management,
            cookie_password,
            session_data,
            client_id,
            // TODO
            jwks: JwkSet { keys: vec![] },
        }
    }

    /// Unseals the session data and checks if the session is still valid.
    pub fn authenticate(&self) -> AuthenticatieWithSessionCookieResponse {
        let Ok(session) = Self::unseal_data(self.session_data, self.cookie_password) else {
            return AuthenticatieWithSessionCookieResponse::Failure(
                AuthenticatieWithSessionCookieFailureResponse {
                    reason: AuthenticatieWithSessionCookieFailureReason::InvalidSessionCookie,
                },
            );
        };

        let Ok(Header { alg, kid, .. }) = decode_header(&session.access_token) else {
            return AuthenticatieWithSessionCookieResponse::Failure(
                AuthenticatieWithSessionCookieFailureResponse {
                    reason: AuthenticatieWithSessionCookieFailureReason::InvalidJwt,
                },
            );
        };

        let Some(key) = kid.and_then(|kid| {
            self.jwks
                .find(&kid)
                .and_then(|jwk| DecodingKey::from_jwk(jwk).ok())
        }) else {
            return AuthenticatieWithSessionCookieResponse::Failure(
                AuthenticatieWithSessionCookieFailureResponse {
                    reason: AuthenticatieWithSessionCookieFailureReason::InvalidJwt,
                },
            );
        };

        let Ok(decoded) =
            decode::<AccessTokenClaims>(&session.access_token, &key, &Validation::new(alg))
        else {
            return AuthenticatieWithSessionCookieResponse::Failure(
                AuthenticatieWithSessionCookieFailureResponse {
                    reason: AuthenticatieWithSessionCookieFailureReason::InvalidJwt,
                },
            );
        };

        AuthenticatieWithSessionCookieResponse::Success(Box::new(
            AuthenticatieWithSessionCookieSuccessResponse {
                session_id: decoded.claims.sid.into(),
                organization_id: decoded.claims.org_id.map(Into::into),
                role: decoded.claims.role.map(Into::into),
                permissions: decoded.claims.permissions,
                entitlements: decoded.claims.entitlements,
                feature_flags: decoded.claims.feature_flags,
                user: session.user,
                impersonator: session.impersonator,
                access_token: session.access_token,
            },
        ))
    }

    /// Refreshes the user’s session with the refresh token.
    ///
    /// Passing in a new organization ID will switch the user to that organization.
    pub async fn refresh(&self, options: &RefreshOptions<'_>) {
        todo!()
    }

    /// Returns a logout URL the user's browser should be redirected to.
    pub fn get_logout_url(&self, options: &GetLogoutUrlOptions) -> Result<Url, GetLogoutUrlError> {
        let authentication_response = self.authenticate();

        match authentication_response {
            AuthenticatieWithSessionCookieResponse::Failure(
                AuthenticatieWithSessionCookieFailureResponse { reason },
            ) => Err(GetLogoutUrlError::Authenticate(reason)),
            AuthenticatieWithSessionCookieResponse::Success(authentication_response) => {
                Ok(self.user_management.get_logout_url(&GetLogoutUrlParams {
                    session_id: &authentication_response.session_id,
                    return_to: options.return_to,
                })?)
            }
        }
    }

    fn unseal_data(sealed_data: &str, key: &[u8]) -> Result<SessionCookieData, DecodeError> {
        let decoded_data = BASE64_STANDARD.decode(sealed_data)?;
        let iv = &decoded_data[0..11];
        let encrypted_data = &decoded_data[12..];

        let cipher = Aes256Gcm::new(Key::from_slice(key));

        let decrypted_data = cipher.decrypt(&Nonce::from_slice(iv), encrypted_data)?;

        todo!()
    }
}
