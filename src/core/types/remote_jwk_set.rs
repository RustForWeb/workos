use std::sync::{Arc, Mutex};

use chrono::{DateTime, FixedOffset, TimeDelta, Utc};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use thiserror::Error;
use url::Url;

use crate::{ResponseExt, WorkOsError, WorkOsResult, user_management::GetJwksError};

type Entry = (JwkSet, DateTime<FixedOffset>);

/// An error returned from [`RemoteJwkSet::find`].
#[derive(Debug, Error)]
pub enum FindJwkError {
    /// Get JWKS error.
    #[error(transparent)]
    GetJwks(WorkOsError<GetJwksError>),

    /// Poison error.
    #[error("poison error: {0}")]
    Poison(String),
}

impl From<FindJwkError> for WorkOsError<FindJwkError> {
    fn from(value: FindJwkError) -> Self {
        Self::Operation(value)
    }
}

/// Remote JSON Web Key Set (JWKS).
#[derive(Clone)]
pub struct RemoteJwkSet {
    client: reqwest::Client,
    url: Url,
    jwks: Arc<Mutex<Option<Entry>>>,
}

impl RemoteJwkSet {
    pub(crate) fn new(client: reqwest::Client, url: Url) -> Self {
        RemoteJwkSet {
            client,
            url,
            jwks: Arc::new(Mutex::new(None)),
        }
    }

    /// Find the key in the set that matches the given key id, if any.
    pub async fn find(&self, kid: &str) -> WorkOsResult<Option<Jwk>, FindJwkError> {
        {
            let jwks = self
                .jwks
                .lock()
                .map_err(|err| FindJwkError::Poison(err.to_string()))?;

            if let Some((jwks, expires_at)) = jwks.as_ref()
                && *expires_at > Utc::now().fixed_offset()
            {
                return Ok(jwks.find(kid).cloned());
            }
        }

        let new_jwks = self
            .client
            .get(self.url.as_str())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<JwkSet>()
            .await?;

        let key = new_jwks.find(kid).cloned();

        // TODO: Consider using the expiry of keys instead?
        let mut jwks = self
            .jwks
            .lock()
            .map_err(|err| FindJwkError::Poison(err.to_string()))?;

        *jwks = Some((new_jwks, Utc::now().fixed_offset() + TimeDelta::minutes(5)));

        Ok(key)
    }
}
