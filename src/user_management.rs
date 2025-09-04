//! A module for interacting with the WorkOS User Management API.
//!
//! [WorkOS Docs: User Management](https://workos.com/docs/user-management)

mod cookie_session;
mod operations;
mod types;

use std::sync::{Arc, Mutex};

pub use cookie_session::*;
pub use operations::*;
use thiserror::Error;
pub use types::*;

use crate::{RemoteJwkSet, WorkOs};

/// An error returned from [`UserManagement::jwks`].
#[derive(Debug, Error)]
pub enum JwksError {
    /// Missing client ID
    #[error("missing client ID")]
    MissingClientId,

    /// Poison error.
    #[error("poison error: {0}")]
    Poison(String),

    /// URL error.
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

/// User Management.
///
/// [WorkOS Docs: User Management](https://workos.com/docs/user-management)
pub struct UserManagement<'a> {
    workos: &'a WorkOs,
    jwks: Arc<Mutex<Option<RemoteJwkSet>>>,
}

impl<'a> UserManagement<'a> {
    /// Returns a new [`UserManagement`] instance for the provided WorkOS client.
    pub fn new(workos: &'a WorkOs) -> Self {
        Self {
            workos,
            jwks: Arc::new(Mutex::new(None)),
        }
    }

    /// Get remote JSON Web Key Set (JWKS).
    pub fn jwks(&'a self) -> Result<RemoteJwkSet, JwksError> {
        let mut jwks = self
            .jwks
            .lock()
            .map_err(|err| JwksError::Poison(err.to_string()))?;

        if let Some(jwks) = jwks.as_ref() {
            return Ok(jwks.clone());
        }

        let Some(client_id) = self.workos.client_id() else {
            return Err(JwksError::MissingClientId);
        };

        let new_jwks =
            RemoteJwkSet::new(self.workos.client().clone(), self.get_jwks_url(client_id)?);

        *jwks = Some(new_jwks.clone());

        Ok(new_jwks)
    }

    /// Load the session by providing the sealed session and the cookie password.
    pub fn load_sealed_session(
        &'a self,
        session_data: &'a str,
        cookie_password: &'a str,
    ) -> CookieSession<'a> {
        CookieSession::new(self, session_data, cookie_password)
    }
}
