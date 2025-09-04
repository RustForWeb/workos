use aead::{AeadCore, OsRng};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use base64::{Engine, prelude::BASE64_STANDARD};
use jsonwebtoken::{DecodingKey, Header, Validation, decode, decode_header};
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    organizations::OrganizationId,
    user_management::{
        AccessTokenClaims, AuthenticateWithRefreshToken, AuthenticateWithRefreshTokenParams,
        AuthenticateWithSessionCookieError, AuthenticateWithSessionCookieResponse, GetLogoutUrl,
        GetLogoutUrlParams, RefreshSessionError, RefreshSessionResponse, SessionCookieData,
        UserManagement,
    },
};

/// The options for [`CookieSession::refresh`].
#[derive(Debug, Default)]
pub struct RefreshOptions<'a> {
    /// The password with which to encrypt the new session.
    ///
    /// Only pass this in if you want to set a new password separate from the one provided in [`UserManagement::load_sealed_session`].
    pub cookie_password: Option<&'a str>,

    /// The organization ID to use for the new session cookie. Use this if you want to switch organizations.
    pub organization_id: Option<&'a OrganizationId>,
}

/// The options for [`CookieSession::get_logout_url`].
#[derive(Debug, Default)]
pub struct GetLogoutUrlOptions<'a> {
    /// The location the user's browser should be redirected to by the WorkOS API after the session has been ended.
    pub return_to: Option<&'a Url>,
}

/// An error returned from [`CookieSession::get_logout_url`].
#[derive(Debug, Error)]
pub enum GetLogoutUrlError {
    /// Authenticate error.
    #[error(transparent)]
    Authenticate(#[from] AuthenticateWithSessionCookieError),

    /// URL error.
    #[error(transparent)]
    Url(#[from] ParseError),
}

/// An error returned from [`CookieSession::seal_data`].
#[derive(Debug, Error)]
pub enum SealDataError {
    /// AES-GCM error.
    #[error(transparent)]
    AesGcm(#[from] aes_gcm::Error),

    /// JSON error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// An error returned from [`CookieSession::unseal_data`].
#[derive(Debug, Error)]
pub enum UnsealDataError {
    /// Not enough data error.
    #[error("not enough data")]
    NotEnoughData,

    /// AES-GCM error.
    #[error(transparent)]
    AesGcm(#[from] aes_gcm::Error),

    /// Base64 decode error.
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    /// JSON error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Cookie session.
pub struct CookieSession<'a> {
    user_management: &'a UserManagement<'a>,
    cookie_password: &'a str,
    session_data: String,

    /// When provided, this is used instead of the JWKS. Should only be used in tests.
    decoding_key: Option<DecodingKey>,
}

impl<'a> CookieSession<'a> {
    pub(crate) fn new(
        user_management: &'a UserManagement<'a>,
        session_data: &'a str,
        cookie_password: &'a str,
    ) -> Self {
        Self {
            user_management,
            cookie_password,
            session_data: session_data.to_string(),
            decoding_key: None,
        }
    }

    /// Unseals the session data and checks if the session is still valid.
    pub async fn authenticate(
        &'a self,
    ) -> Result<AuthenticateWithSessionCookieResponse, AuthenticateWithSessionCookieError> {
        let session = Self::unseal_data(&self.session_data, self.cookie_password)?;

        let Header { alg, kid, .. } = decode_header(&*session.access_token)?;

        let key = if let Some(decoding_key) = &self.decoding_key {
            decoding_key.clone()
        } else {
            let kid = kid.ok_or(AuthenticateWithSessionCookieError::MissingJwkId)?;

            let jwks = self.user_management.jwks()?;
            let jwk = jwks
                .find(&kid)
                .await?
                .ok_or(AuthenticateWithSessionCookieError::JwkNotFound)?;

            DecodingKey::from_jwk(&jwk)?
        };

        let mut validation = Validation::new(alg);
        validation.set_required_spec_claims(&Vec::<String>::with_capacity(0));

        let decoded = decode::<AccessTokenClaims>(&*session.access_token, &key, &validation)?;

        Ok(AuthenticateWithSessionCookieResponse {
            session_id: decoded.claims.sid.into(),
            organization_id: decoded.claims.org_id.map(Into::into),
            role: decoded.claims.role.map(Into::into),
            permissions: decoded.claims.permissions,
            entitlements: decoded.claims.entitlements,
            feature_flags: decoded.claims.feature_flags,
            user: session.user,
            impersonator: session.impersonator,
            access_token: session.access_token,
        })
    }

    /// Refreshes the user’s session with the refresh token.
    ///
    /// Passing in a new organization ID will switch the user to that organization.
    pub async fn refresh(
        &mut self,
        options: &RefreshOptions<'a>,
    ) -> Result<RefreshSessionResponse, RefreshSessionError> {
        let session = Self::unseal_data(&self.session_data, self.cookie_password)?;

        let cookie_password = options.cookie_password.unwrap_or(self.cookie_password);

        let response = self
            .user_management
            .authenticate_with_refresh_token(&AuthenticateWithRefreshTokenParams {
                client_id: self
                    .user_management
                    .workos
                    .client_id()
                    .ok_or(RefreshSessionError::MissingClientId)?,
                refresh_token: &session.refresh_token,
                organization_id: options.organization_id.or(session.organization_id.as_ref()),
                ip_address: None,
                user_agent: None,
            })
            .await?;
        let sealed_session = response.sealed_session(cookie_password)?;

        self.session_data = sealed_session.clone();
        self.cookie_password = cookie_password;

        Ok(RefreshSessionResponse {
            sealed_session,
            session: response,
        })
    }

    /// Returns a logout URL the user's browser should be redirected to.
    pub async fn get_logout_url(
        &'a self,
        options: &GetLogoutUrlOptions<'_>,
    ) -> Result<Url, GetLogoutUrlError> {
        let authentication_response = self.authenticate().await?;

        Ok(self.user_management.get_logout_url(&GetLogoutUrlParams {
            session_id: &authentication_response.session_id,
            return_to: options.return_to,
        })?)
    }

    /// Encrypts and seals data using AES-256-GCM.
    pub(crate) fn seal_data(data: SessionCookieData, key: &str) -> Result<String, SealDataError> {
        let iv = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(&Self::key(key));

        let decrypted_data = serde_json::to_string(&data)?;

        let encrypted_data = cipher.encrypt(&iv, decrypted_data.as_ref())?;

        let encoded_data =
            BASE64_STANDARD.encode(iv.into_iter().chain(encrypted_data).collect::<Vec<u8>>());

        Ok(encoded_data)
    }

    ///  Decrypts and unseals data using AES-256-GCM.
    fn unseal_data(sealed_data: &str, key: &str) -> Result<SessionCookieData, UnsealDataError> {
        let decoded_data = BASE64_STANDARD.decode(sealed_data)?;

        if decoded_data.len() < 12 {
            return Err(UnsealDataError::NotEnoughData);
        }

        let iv = &decoded_data[0..12];
        let encrypted_data = &decoded_data[12..];

        let cipher = Aes256Gcm::new(&Self::key(key));

        let decrypted_data = cipher.decrypt(Nonce::from_slice(iv), encrypted_data)?;

        Ok(serde_json::from_slice(&decrypted_data)?)
    }

    fn key(key: &str) -> Key<Aes256Gcm> {
        let key = key.as_bytes();
        let length = key.len().min(32);

        let mut key_data = [0u8; 32];
        key_data[..length].copy_from_slice(&key[0..length]);

        Key::<Aes256Gcm>::from(key_data)
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::DecodingKey;
    use mockito::{Matcher, Server};
    use serde_json::json;
    use url::Url;

    use crate::{
        ApiKey, Timestamps, WorkOs,
        organizations::OrganizationId,
        roles::RoleSlug,
        sso::{AccessToken, ClientId},
        user_management::{
            AuthenticateWithSessionCookieError, AuthenticateWithSessionCookieResponse,
            CookieSession, GetLogoutUrlError, GetLogoutUrlOptions, Impersonator, RefreshOptions,
            RefreshSessionError, RefreshToken, SessionCookieData, SessionId, User, UserId,
        },
    };

    fn before() -> WorkOs {
        WorkOs::builder(&ApiKey::from("sk_test_Sz3IQjepeSWaI4cMS4ms4sMuU"))
            .client_id(&ClientId::from("client_123"))
            .build()
    }

    fn before_with_base_url(base_url: &str) -> WorkOs {
        WorkOs::builder(&ApiKey::from("sk_test_Sz3IQjepeSWaI4cMS4ms4sMuU"))
            .client_id(&ClientId::from("client_123"))
            .base_url(base_url)
            .unwrap()
            .build()
    }

    #[tokio::test]
    async fn authenticate_returns_a_failed_response_if_no_access_token_is_found_in_the_session_data()
     {
        let workos = before();

        let user_management = workos.user_management();
        let session = user_management.load_sealed_session("sessionData", "cookiePassword");

        let response = session.authenticate().await;

        assert!(matches!(
            response,
            Err(AuthenticateWithSessionCookieError::InvalidSessionCookie(_)),
        ));
    }

    #[tokio::test]
    async fn authenticate_returns_a_failed_response_if_the_access_token_is_not_a_valid_jwt() {
        let workos = before();

        let cookie_password = "alongcookiesecretmadefortestingsessions";

        let session_data = CookieSession::seal_data(
            SessionCookieData {
                access_token: AccessToken::from("ewogICJzdWIiOiAiMTIzNDU2Nzg5MCIsCiAgIm5hbWUiOiAiSm9obiBEb2UiLAogICJpYXQiOiAxNTE2MjM5MDIyLAogICJzaWQiOiAic2Vzc2lvbl8xMjMiLAogICJvcmdfaWQiOiAib3JnXzEyMyIsCiAgInJvbGUiOiAibWVtYmVyIiwKICAicGVybWlzc2lvbnMiOiBbInBvc3RzOmNyZWF0ZSIsICJwb3N0czpkZWxldGUiXQp9"),
                refresh_token: RefreshToken::from( "def456"),
                user: User {
                    id: UserId::from("user_01H5JQDV7R7ATEYZDEG0W5PRYS"),
                    email: "test@example.com".to_string(),
                    email_verified: true,
                    first_name: None,
                    last_name: None,
                    profile_picture_url: None,
                    last_sign_in_at: None,
                    external_id: None,
                    metadata: None,
                    timestamps: Timestamps {
                        created_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                        updated_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                    },
                },
                organization_id: None,
                impersonator: None,
            },
            cookie_password,
        ).unwrap();

        let user_management = workos.user_management();
        let session = user_management.load_sealed_session(&session_data, cookie_password);

        let response = session.authenticate().await;

        assert!(matches!(
            response,
            Err(AuthenticateWithSessionCookieError::InvalidJwt(_)),
        ));
    }

    #[tokio::test]
    async fn authenticate_returns_a_successful_response_if_the_session_data_is_valid() {
        let workos = before();

        let cookie_password = "alongcookiesecretmadefortestingsessions";
        let access_token = AccessToken::from(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoZW50aWNhdGVkIjp0cnVlLCJpbXBlcnNvbmF0b3IiOnsiZW1haWwiOiJhZG1pbkBleGFtcGxlLmNvbSIsInJlYXNvbiI6InRlc3QifSwic2lkIjoic2Vzc2lvbl8xMjMiLCJvcmdfaWQiOiJvcmdfMTIzIiwicm9sZSI6Im1lbWJlciIsInJvbGVzIjpbIm1lbWJlciIsImFkbWluIl0sInBlcm1pc3Npb25zIjpbInBvc3RzOmNyZWF0ZSIsInBvc3RzOmRlbGV0ZSJdLCJlbnRpdGxlbWVudHMiOlsiYXVkaXQtbG9ncyJdLCJmZWF0dXJlX2ZsYWdzIjpbImRhcmstbW9kZSIsImJldGEtZmVhdHVyZXMiXSwidXNlciI6eyJvYmplY3QiOiJ1c2VyIiwiaWQiOiJ1c2VyXzAxSDVKUURWN1I3QVRFWVpERUcwVzVQUllTIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIn19.TNUzJYn6lzLWFFsiWiKEgIshyUs-bKJQf1VxwNr1cGI",
        );
        let decoding_key =
            DecodingKey::from_secret("a-string-secret-at-least-256-bits-long".as_bytes());

        let session_data = CookieSession::seal_data(
            SessionCookieData {
                access_token: access_token.clone(),
                refresh_token: RefreshToken::from("def456"),
                impersonator: Some(Impersonator {
                    email: "admin@example.com".to_string(),
                    reason: Some("test".to_string()),
                }),
                user: User {
                    id: UserId::from("user_01H5JQDV7R7ATEYZDEG0W5PRYS"),
                    email: "test@example.com".to_string(),
                    email_verified: true,
                    first_name: None,
                    last_name: None,
                    profile_picture_url: None,
                    last_sign_in_at: None,
                    external_id: None,
                    metadata: None,
                    timestamps: Timestamps {
                        created_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                        updated_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                    },
                },
                organization_id: None,
            },
            cookie_password,
        )
        .unwrap();

        let user_management = workos.user_management();
        let mut session = user_management.load_sealed_session(&session_data, cookie_password);

        // Use hardcoded decoding key instead of JWKS for testing.
        session.decoding_key = Some(decoding_key);

        let response = session.authenticate().await.unwrap();

        assert_eq!(
            response,
            AuthenticateWithSessionCookieResponse {
                impersonator: Some(Impersonator {
                    email: "admin@example.com".to_string(),
                    reason: Some("test".to_string()),
                }),
                session_id: SessionId::from("session_123"),
                organization_id: Some(OrganizationId::from("org_123")),
                role: Some(RoleSlug::from("member")),
                // roles: ["member", "admin"],
                permissions: Some(vec!["posts:create".to_string(), "posts:delete".to_string()]),
                entitlements: Some(vec!["audit-logs".to_string()]),
                feature_flags: Some(vec!["dark-mode".to_string(), "beta-features".to_string()]),
                user: User {
                    id: UserId::from("user_01H5JQDV7R7ATEYZDEG0W5PRYS"),
                    email: "test@example.com".to_string(),
                    email_verified: true,
                    first_name: None,
                    last_name: None,
                    profile_picture_url: None,
                    last_sign_in_at: None,
                    external_id: None,
                    metadata: None,
                    timestamps: Timestamps {
                        created_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                        updated_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                    },
                },
                access_token,
            }
        )
    }

    #[tokio::test]
    async fn refresh_returns_a_failed_response_if_invalid_session_data_is_provided() {
        let workos = before();

        let user_management = workos.user_management();
        let mut session = user_management.load_sealed_session("", "cookiePassword");

        let response = session.refresh(&RefreshOptions::default()).await;

        assert!(matches!(
            response,
            Err(RefreshSessionError::InvalidSessionCookie(_))
        ));
    }

    #[tokio::test]
    async fn refresh_returns_a_successful_response_if_the_session_data_is_valid() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/user_management/authenticate")
            .match_body(Matcher::PartialJson(json!({
                "client_id": "client_123",
                "client_secret": "sk_test_Sz3IQjepeSWaI4cMS4ms4sMuU",
                "grant_type": "refresh_token",
                "refresh_token": "def456",
            })))
            .with_status(200)
            .with_body(
                json!({
                    "user": {
                        "object": "user",
                        "id": "user_01H5JQDV7R7ATEYZDEG0W5PRYS",
                        "email": "test@example.com",
                        "first_name": null,
                        "last_name": null,
                        "email_verified": true,
                        "profile_picture_url": null,
                        "metadata": {},
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    },
                    "organization_id": "org_123",
                    "access_token": "eyJhb.nNzb19vaWRjX2tleV9.lc5Uk4yWVk5In0",
                    "refresh_token": "yAjhKk123NLIjdrBdGZPf8pLIDvK",
                    "authentication_method": "SSO",
                    "impersonator": {
                        "email": "admin@example.com",
                        "reason": "Investigating an issue with the customer's account."
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let workos = before_with_base_url(&server.url());

        let cookie_password = "alongcookiesecretmadefortestingsessions";
        let access_token = AccessToken::from(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJzaWQiOiJzZXNzaW9uXzEyMyIsIm9yZ19pZCI6Im9yZ18xMjMiLCJyb2xlIjoibWVtYmVyIiwicm9sZXMiOlsibWVtYmVyIiwiYWRtaW4iXSwicGVybWlzc2lvbnMiOlsicG9zdHM6Y3JlYXRlIiwicG9zdHM6ZGVsZXRlIl19.N5zveP149QhRR5zNvzGJPiCX098uXaN8VM1_lwsMg4A",
        );
        let refresh_token = RefreshToken::from("def456");
        let decoding_key =
            DecodingKey::from_secret("a-string-secret-at-least-256-bits-long".as_bytes());

        let session_data = CookieSession::seal_data(
            SessionCookieData {
                access_token,
                refresh_token,
                impersonator: Some(Impersonator {
                    email: "admin@example.com".to_string(),
                    reason: Some("test".to_string()),
                }),
                user: User {
                    id: UserId::from("user_01H5JQDV7R7ATEYZDEG0W5PRYS"),
                    email: "test@example.com".to_string(),
                    email_verified: true,
                    first_name: None,
                    last_name: None,
                    profile_picture_url: None,
                    last_sign_in_at: None,
                    external_id: None,
                    metadata: None,
                    timestamps: Timestamps {
                        created_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                        updated_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                    },
                },
                organization_id: None,
            },
            cookie_password,
        )
        .unwrap();

        let user_management = workos.user_management();
        let mut session = user_management.load_sealed_session(&session_data, cookie_password);

        // Use hardcoded decoding key instead of JWKS for testing.
        session.decoding_key = Some(decoding_key);

        let response = session.refresh(&RefreshOptions::default()).await.unwrap();

        assert_eq!(response.session.user.email, "test@example.com");
    }

    #[tokio::test]
    async fn refresh_overwrites_the_cookie_password_if_a_new_one_is_provided() {
        let access_token = AccessToken::from(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJzaWQiOiJzZXNzaW9uXzEyMyIsIm9yZ19pZCI6Im9yZ18xMjMiLCJyb2xlIjoibWVtYmVyIiwicm9sZXMiOlsibWVtYmVyIiwiYWRtaW4iXSwicGVybWlzc2lvbnMiOlsicG9zdHM6Y3JlYXRlIiwicG9zdHM6ZGVsZXRlIl19.N5zveP149QhRR5zNvzGJPiCX098uXaN8VM1_lwsMg4A",
        );
        let refresh_token = RefreshToken::from("def456");

        let mut server = Server::new_async().await;

        server
            .mock("POST", "/user_management/authenticate")
            .match_body(Matcher::PartialJson(json!({
                "client_id": "client_123",
                "client_secret": "sk_test_Sz3IQjepeSWaI4cMS4ms4sMuU",
                "grant_type": "refresh_token",
                "refresh_token": "def456",
            })))
            .with_status(200)
            .with_body(
                json!({
                    "user": {
                        "object": "user",
                        "id": "user_01H5JQDV7R7ATEYZDEG0W5PRYS",
                        "email": "test@example.com",
                        "first_name": null,
                        "last_name": null,
                        "email_verified": true,
                        "profile_picture_url": null,
                        "metadata": {},
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    },
                    "organization_id": "org_123",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "authentication_method": "SSO",
                    "impersonator": {
                        "email": "admin@example.com",
                        "reason": "Investigating an issue with the customer's account."
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let workos = before_with_base_url(&server.url());

        let cookie_password = "alongcookiesecretmadefortestingsessions";
        let decoding_key =
            DecodingKey::from_secret("a-string-secret-at-least-256-bits-long".as_bytes());

        let session_data = CookieSession::seal_data(
            SessionCookieData {
                access_token,
                refresh_token,
                impersonator: Some(Impersonator {
                    email: "admin@example.com".to_string(),
                    reason: Some("test".to_string()),
                }),
                user: User {
                    id: UserId::from("user_01H5JQDV7R7ATEYZDEG0W5PRYS"),
                    email: "test@example.com".to_string(),
                    email_verified: true,
                    first_name: None,
                    last_name: None,
                    profile_picture_url: None,
                    last_sign_in_at: None,
                    external_id: None,
                    metadata: None,
                    timestamps: Timestamps {
                        created_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                        updated_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                    },
                },
                organization_id: None,
            },
            cookie_password,
        )
        .unwrap();

        let user_management = workos.user_management();
        let mut session = user_management.load_sealed_session(&session_data, cookie_password);

        // Use hardcoded decoding key instead of JWKS for testing.
        session.decoding_key = Some(decoding_key);

        let new_cookie_password = "anevenlongercookiesecretmadefortestingsessions";

        let response = session
            .refresh(&RefreshOptions {
                cookie_password: Some(new_cookie_password),
                organization_id: None,
            })
            .await;

        assert!(response.is_ok());

        let response = session.authenticate().await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn get_logout_url_returns_a_logout_url_for_the_user() {
        let workos = before();

        let cookie_password = "alongcookiesecretmadefortestingsessions";
        let decoding_key =
            DecodingKey::from_secret("a-string-secret-at-least-256-bits-long".as_bytes());

        let session_data = CookieSession::seal_data(
            SessionCookieData {
                access_token: AccessToken::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJzaWQiOiJzZXNzaW9uXzEyMyIsIm9yZ19pZCI6Im9yZ18xMjMiLCJyb2xlIjoibWVtYmVyIiwicGVybWlzc2lvbnMiOlsicG9zdHM6Y3JlYXRlIiwicG9zdHM6ZGVsZXRlIl19.3__E4RSr5WipYXEd5qcrstOcE263jXwxp3IuxG30rcM"),
                refresh_token: RefreshToken::from("def456"),
                impersonator: None,
                user: User {
                    id: UserId::from("user_01H5JQDV7R7ATEYZDEG0W5PRYS"),
                    email: "test@example.com".to_string(),
                    email_verified: true,
                    first_name: None,
                    last_name: None,
                    profile_picture_url: None,
                    last_sign_in_at: None,
                    external_id: None,
                    metadata: None,
                    timestamps: Timestamps {
                        created_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                        updated_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                    },
                },
                organization_id: None,
            },
            cookie_password,
        )
        .unwrap();

        let user_management = workos.user_management();
        let mut session = user_management.load_sealed_session(&session_data, cookie_password);

        // Use hardcoded decoding key instead of JWKS for testing.
        session.decoding_key = Some(decoding_key);

        let url = session
            .get_logout_url(&GetLogoutUrlOptions::default())
            .await
            .unwrap();

        assert_eq!(
            url.to_string(),
            "https://api.workos.com/user_management/sessions/logout?session_id=session_123"
        );
    }

    #[tokio::test]
    async fn get_logout_url_returns_an_error_if_the_session_is_invalid() {
        let workos = before();

        let user_management = workos.user_management();
        let session = user_management.load_sealed_session("", "cookiePassword");

        let response = session
            .get_logout_url(&GetLogoutUrlOptions::default())
            .await;

        assert!(matches!(
            response,
            Err(GetLogoutUrlError::Authenticate(
                AuthenticateWithSessionCookieError::InvalidSessionCookie(_)
            )),
        ));
    }

    #[tokio::test]
    async fn get_logout_url_when_a_return_url_is_provided_returns_a_logout_url_for_the_user() {
        let workos = before();

        let cookie_password = "alongcookiesecretmadefortestingsessions";
        let decoding_key =
            DecodingKey::from_secret("a-string-secret-at-least-256-bits-long".as_bytes());

        let session_data = CookieSession::seal_data(
            SessionCookieData {
                access_token: AccessToken::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJzaWQiOiJzZXNzaW9uXzEyMyIsIm9yZ19pZCI6Im9yZ18xMjMiLCJyb2xlIjoibWVtYmVyIiwicGVybWlzc2lvbnMiOlsicG9zdHM6Y3JlYXRlIiwicG9zdHM6ZGVsZXRlIl19.3__E4RSr5WipYXEd5qcrstOcE263jXwxp3IuxG30rcM"),
                refresh_token: RefreshToken::from("def456"),
                impersonator: None,
                user: User {
                    id: UserId::from("user_01H5JQDV7R7ATEYZDEG0W5PRYS"),
                    email: "test@example.com".to_string(),
                    email_verified: true,
                    first_name: None,
                    last_name: None,
                    profile_picture_url: None,
                    last_sign_in_at: None,
                    external_id: None,
                    metadata: None,
                    timestamps: Timestamps {
                        created_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                        updated_at: "2021-06-25T19:07:33.155Z".try_into().unwrap(),
                    },
                },
                organization_id: None,
            },
            cookie_password,
        )
        .unwrap();

        let user_management = workos.user_management();
        let mut session = user_management.load_sealed_session(&session_data, cookie_password);

        // Use hardcoded decoding key instead of JWKS for testing.
        session.decoding_key = Some(decoding_key);

        let url = session
            .get_logout_url(&GetLogoutUrlOptions {
                return_to: Some(&Url::parse("https://example.com/signed-out").unwrap()),
            })
            .await
            .unwrap();

        assert_eq!(
            url.to_string(),
            "https://api.workos.com/user_management/sessions/logout?session_id=session_123&return_to=https%3A%2F%2Fexample.com%2Fsigned-out"
        );
    }
}
