use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

use crate::mfa::AuthenticationFactorId;
use crate::{Timestamp, Timestamps};

/// The ID of an [`AuthenticationChallenge`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct AuthenticationChallengeId(String);

/// [WorkOS Docs: Authentication Challenge](https://workos.com/docs/reference/mfa/authentication-challenge)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    /// The unique ID of the authentication challenge.
    pub id: AuthenticationChallengeId,

    /// The unique ID of the authentication factor the challenge belongs to.
    pub authentication_factor_id: AuthenticationFactorId,

    /// The timestamp when the authentication challenge will expire.
    ///
    /// This will always be [`None`] for time-based one-time password (TOTP) factors.
    pub expires_at: Option<Timestamp>,

    /// The timestamps for the authentication challenge.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::Timestamps;

    use super::*;

    #[test]
    fn it_deserializes_an_authentication_challenge() {
        let challenge: AuthenticationChallenge = serde_json::from_str(
            &json!({
              "object": "authentication_challenge",
              "id": "auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5",
              "authentication_factor_id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
              "expires_at": "2022-02-15T15:36:53.279Z",
              "created_at": "2022-02-15T15:26:53.274Z",
              "updated_at": "2022-02-15T15:26:53.274Z"
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(
            challenge,
            AuthenticationChallenge {
                id: AuthenticationChallengeId::from("auth_challenge_01FVYZWQTZQ5VB6BC5MPG2EYC5"),
                authentication_factor_id: AuthenticationFactorId::from(
                    "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ"
                ),
                expires_at: Timestamp::try_from("2022-02-15T15:36:53.279Z").ok(),
                timestamps: Timestamps {
                    created_at: Timestamp::try_from("2022-02-15T15:26:53.274Z").unwrap(),
                    updated_at: Timestamp::try_from("2022-02-15T15:26:53.274Z").unwrap(),
                }
            }
        )
    }
}
