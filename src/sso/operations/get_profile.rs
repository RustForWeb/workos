use async_trait::async_trait;
use thiserror::Error;

use crate::sso::{AccessToken, Profile, Sso};
use crate::{ResponseExt, WorkOsResult};

/// An error returned from [`GetProfile`].
#[derive(Debug, Error)]
pub enum GetProfileError {}

/// [WorkOS Docs: Get a User Profile](https://workos.com/docs/reference/sso/profile/user)
#[async_trait]
pub trait GetProfile {
    /// [WorkOS Docs: Get a User Profile](https://workos.com/docs/reference/sso/profile/user)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::sso::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetProfileError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let profile = workos
    ///     .sso()
    ///     .get_profile(&AccessToken::from("01DMEK0J53CVMC32CK5SE0KZ8Q"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_profile(
        &self,
        access_token: &AccessToken,
    ) -> WorkOsResult<Profile, GetProfileError>;
}

#[async_trait]
impl GetProfile for Sso<'_> {
    async fn get_profile(
        &self,
        access_token: &AccessToken,
    ) -> WorkOsResult<Profile, GetProfileError> {
        let url = self.workos.base_url().join("/sso/profile")?;
        let get_profile_response = self
            .workos
            .client()
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<Profile>()
            .await?;

        Ok(get_profile_response)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::sso::ProfileId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_profile_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/sso/profile")
            .match_header("Authorization", "Bearer 01DMEK0J53CVMC32CK5SE0KZ8Q")
            .with_status(200)
            .with_body(
                json!({
                  "id": "prof_01DMC79VCBZ0NY2099737PSVF1",
                  "connection_id": "conn_01E4ZCR3C56J083X43JQXF3JK5",
                  "connection_type": "okta",
                  "email": "todd@foo-corp.com",
                  "first_name": "Todd",
                  "idp_id": "00u1a0ufowBJlzPlk357",
                  "last_name": "Rundgren",
                  "object": "profile",
                  "raw_attributes": {}
                })
                .to_string(),
            )
            .create_async()
            .await;

        let profile = workos
            .sso()
            .get_profile(&AccessToken::from("01DMEK0J53CVMC32CK5SE0KZ8Q"))
            .await
            .unwrap();

        assert_eq!(
            profile.id,
            ProfileId::from("prof_01DMC79VCBZ0NY2099737PSVF1")
        )
    }
}
