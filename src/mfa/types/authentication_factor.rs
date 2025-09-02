use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

use crate::Timestamps;

/// The ID of an [`AuthenticationFactor`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct AuthenticationFactorId(String);

/// The type of the authentication factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationFactorTypeString {
    /// Time-based one-time password (TOTP).
    Totp,

    /// One-time password via SMS message.
    Sms,
}

/// The ID and name of an [`AuthenticationFactor`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct AuthenticationFactorIdAndType {
    /// The unique ID of the authentication factor.
    pub id: AuthenticationFactorId,

    /// The type of the authentication factor.
    pub r#type: AuthenticationFactorTypeString,
}

/// [WorkOS Docs: Authentication Factor](https://workos.com/docs/reference/mfa/authentication-factor)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationFactor {
    /// The unique ID of the authentication factor.
    pub id: AuthenticationFactorId,

    /// The type of the authentication factor.
    #[serde(flatten)]
    pub r#type: AuthenticationFactorType,

    /// The timestamps for the authentication factor.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}

/// The type of an [`AuthenticationFactor`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationFactorType {
    /// Time-based one-time password (TOTP).
    Totp {
        /// Your application or company name displayed in the user's authenticator app. Defaults to your WorkOS team name.
        issuer: String,

        /// The user's account name displayed in their authenticator app. Defaults to the user's email.
        user: String,

        /// Base64 encoded image containing scannable QR code.
        qr_code: String,

        /// TOTP secret that can be manually entered into some authenticator apps in place of scanning a QR code.
        secret: String,

        /// The `otpauth` URI that is encoded by the provided `qr_code`.
        uri: String,
    },
    /// One-time password via SMS message.
    Sms {
        /// The phone number the factor was enrolled with.
        phone_number: String,
    },
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{Timestamp, Timestamps};

    use super::*;

    #[test]
    fn it_deserializes_a_totp_factor() {
        let factor: AuthenticationFactor = serde_json::from_str(&json!({
            "object": "authentication_factor",
            "id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
            "created_at": "2022-02-15T15:14:19.392Z",
            "updated_at": "2022-02-15T15:14:19.392Z",
            "type": "totp",
            "totp": {
                "issuer": "Foo Corp",
                "user": "alan.turing@foo-corp.com",
                "qr_code": "data:image/png;base64,{base64EncodedPng}",
                "secret": "NAGCCFS3EYRB422HNAKAKY3XDUORMSRF",
                "uri": "otpauth://totp/FooCorp:alan.turing@foo-corp.com?secret=NAGCCFS3EYRB422HNAKAKY3XDUORMSRF&issuer=FooCorp"
            }
          }).to_string()).unwrap();

        assert_eq!(
            factor,
            AuthenticationFactor {
                id: AuthenticationFactorId::from("auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ"),
                r#type: AuthenticationFactorType::Totp {
                    issuer: "Foo Corp".to_string(),
                    user: "alan.turing@foo-corp.com".to_string(),
                    qr_code: "data:image/png;base64,{base64EncodedPng}".to_string(),
                    secret: "NAGCCFS3EYRB422HNAKAKY3XDUORMSRF".to_string(),
                    uri: "otpauth://totp/FooCorp:alan.turing@foo-corp.com?secret=NAGCCFS3EYRB422HNAKAKY3XDUORMSRF&issuer=FooCorp".to_string()
                },
                timestamps: Timestamps {
                    created_at: Timestamp::try_from("2022-02-15T15:14:19.392Z").unwrap(),
                    updated_at: Timestamp::try_from("2022-02-15T15:14:19.392Z").unwrap(),
                },
            }
        )
    }

    #[test]
    fn it_deserializes_an_sms_factor() {
        let factor: AuthenticationFactor = serde_json::from_str(
            &json!({
              "object": "authentication_factor",
              "id": "auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ",
              "created_at": "2022-02-15T15:14:19.392Z",
              "updated_at": "2022-02-15T15:14:19.392Z",
              "type": "sms",
              "sms": {
                  "phone_number": "+15005550006"
              }
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(
            factor,
            AuthenticationFactor {
                id: AuthenticationFactorId::from("auth_factor_01FVYZ5QM8N98T9ME5BCB2BBMJ"),
                r#type: AuthenticationFactorType::Sms {
                    phone_number: "+15005550006".to_string()
                },
                timestamps: Timestamps {
                    created_at: Timestamp::try_from("2022-02-15T15:14:19.392Z").unwrap(),
                    updated_at: Timestamp::try_from("2022-02-15T15:14:19.392Z").unwrap(),
                },
            }
        )
    }
}
