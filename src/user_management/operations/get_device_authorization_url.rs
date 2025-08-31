use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::sso::ClientId;
use crate::user_management::{DeviceCode, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`GetDeviceAuthorizationUrl`].
#[derive(Debug, Serialize)]
pub struct GetDeviceAuthorizationUrlParams<'a> {
    /// The WorkOS client ID for your application.
    pub client_id: &'a ClientId,
}

/// The response for [`GetDeviceAuthorizationUrl`].
#[derive(Debug, Deserialize)]
pub struct GetDeviceAuthorizationUrlResponse {
    /// A unique identifier for this authorization request. Use this when polling the token endpoint.
    pub device_code: DeviceCode,

    /// A short, user-friendly code that users enter to authorize the device.
    pub user_code: String,

    /// The URL where users can enter the user code to authorize the device.
    pub verification_uri: Url,

    /// A URL with the user code pre-filled, allowing one-click authorization.
    pub verification_uri_complete: Url,

    /// The lifetime of the device code and user code in seconds.
    pub expires_in: u64,

    /// The minimum interval in seconds between token requests.
    pub interval: u64,
}

/// An error returned from [`GetDeviceAuthorizationUrl`].
#[derive(Debug, Error)]
pub enum GetDeviceAuthorizationUrlError {}

impl From<GetDeviceAuthorizationUrlError> for WorkOsError<GetDeviceAuthorizationUrlError> {
    fn from(err: GetDeviceAuthorizationUrlError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get device authorization URL](https://workos.com/docs/reference/user-management/cli-auth/device-authorization)
#[async_trait]
pub trait GetDeviceAuthorizationUrl {
    /// Initiates the CLI Auth flow by requesting a device code and verification URLs.
    ///
    /// [WorkOS Docs: Get device authorization URL](https://workos.com/docs/reference/user-management/cli-auth/device-authorization)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::sso::ClientId;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetDeviceAuthorizationUrlError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let response = workos
    ///     .user_management()
    ///     .get_device_authorization_url(&GetDeviceAuthorizationUrlParams {
    ///         client_id: &ClientId::from("client_123456789"),
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_device_authorization_url(
        &self,
        params: &GetDeviceAuthorizationUrlParams<'_>,
    ) -> WorkOsResult<GetDeviceAuthorizationUrlResponse, GetDeviceAuthorizationUrlError>;
}

#[async_trait]
impl GetDeviceAuthorizationUrl for UserManagement<'_> {
    async fn get_device_authorization_url(
        &self,
        params: &GetDeviceAuthorizationUrlParams<'_>,
    ) -> WorkOsResult<GetDeviceAuthorizationUrlResponse, GetDeviceAuthorizationUrlError> {
        let url = self
            .workos
            .base_url()
            .join("/user_management/authorize/device")?;

        let response = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .form(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<GetDeviceAuthorizationUrlResponse>()
            .await?;

        Ok(response)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_device_authorization_url_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/authorize/device")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .match_body(Matcher::UrlEncoded("client_id".to_string(), "client_123456789".to_string()))
            .with_status(200)
            .with_body(
                json!({
                    "device_code": "CVE2wOfIFK4vhmiDBntpX9s8KT2f0qngpWYL0LGy9HxYgBRXUKIUkZB9BgIFho5h",
                    "user_code": "BCDF-GHJK",
                    "verification_uri": "https://foo-corp.authkit.app/device",
                    "verification_uri_complete": "https://foo-corp.authkit.app/device?user_code=BCDF-GHJK",
                    "expires_in": 300,
                    "interval": 5
                })
                .to_string(),
            )
            .create_async()
            .await;

        let response = workos
            .user_management()
            .get_device_authorization_url(&GetDeviceAuthorizationUrlParams {
                client_id: &ClientId::from("client_123456789"),
            })
            .await
            .unwrap();

        assert_eq!(
            response.device_code,
            DeviceCode::from("CVE2wOfIFK4vhmiDBntpX9s8KT2f0qngpWYL0LGy9HxYgBRXUKIUkZB9BgIFho5h")
        );
        assert_eq!(response.user_code, "BCDF-GHJK");
    }
}
