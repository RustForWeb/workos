use url::{ParseError, Url};

use crate::ApiKey;
use crate::directory_sync::DirectorySync;
use crate::events::Events;
use crate::mfa::Mfa;
use crate::organization_domains::OrganizationDomains;
use crate::organizations::Organizations;
use crate::portal::Portal;
use crate::roles::Roles;
use crate::sso::Sso;
use crate::user_management::UserManagement;
use crate::widgets::Widgets;

/// The WorkOS client.
#[derive(Clone)]
pub struct WorkOs {
    base_url: Url,
    key: ApiKey,
    client: reqwest::Client,
}

impl WorkOs {
    /// Returns a new instance of the WorkOS client using the provided API key.
    pub fn new(key: &ApiKey) -> Self {
        WorkOsBuilder::new(key).build()
    }

    /// Returns a [`WorkOsBuilder`] that may be used to construct a WorkOS client.
    pub fn builder(key: &ApiKey) -> WorkOsBuilder<'_> {
        WorkOsBuilder::new(key)
    }

    pub(crate) fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub(crate) fn key(&self) -> &ApiKey {
        &self.key
    }

    pub(crate) fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Returns a [`DirectorySync`] instance.
    pub fn directory_sync(&self) -> DirectorySync<'_> {
        DirectorySync::new(self)
    }

    /// Returns an [`Events`] instance.
    pub fn events(&self) -> Events<'_> {
        Events::new(self)
    }

    /// Returns an [`Mfa`] instance.
    pub fn mfa(&self) -> Mfa<'_> {
        Mfa::new(self)
    }

    /// Returns an [`OrganizationDomains`] instance.
    pub fn organization_domains(&self) -> OrganizationDomains<'_> {
        OrganizationDomains::new(self)
    }

    /// Returns an [`Organizations`] instance.
    pub fn organizations(&self) -> Organizations<'_> {
        Organizations::new(self)
    }

    /// Returns a [`Portal`] instance.
    pub fn portal(&self) -> Portal<'_> {
        Portal::new(self)
    }

    /// Returns a [`Roles`] instance.
    pub fn roles(&self) -> Roles<'_> {
        Roles::new(self)
    }

    /// Returns an [`Sso`] instance.
    pub fn sso(&self) -> Sso<'_> {
        Sso::new(self)
    }

    /// Returns a [`UserManagement`] instance.
    pub fn user_management(&self) -> UserManagement<'_> {
        UserManagement::new(self)
    }

    /// Returns an [`Widgets`] instance.
    pub fn widgets(&self) -> Widgets<'_> {
        Widgets::new(self)
    }
}

/// A builder for a WorkOS client.
pub struct WorkOsBuilder<'a> {
    base_url: Url,
    key: &'a ApiKey,
}

impl<'a> WorkOsBuilder<'a> {
    /// Returns a new [`WorkOsBuilder`] using the provided API key.
    pub fn new(key: &'a ApiKey) -> Self {
        Self {
            base_url: Url::parse("https://api.workos.com").unwrap(),
            key,
        }
    }

    /// Sets the base URL of the WorkOS API that the client should point to.
    pub fn base_url(mut self, base_url: &'a str) -> Result<Self, ParseError> {
        self.base_url = Url::parse(base_url)?;
        Ok(self)
    }

    /// Sets the API key that the client will use.
    pub fn key(mut self, key: &'a ApiKey) -> Self {
        self.key = key;
        self
    }

    /// Consumes the builder and returns the constructed client.
    pub fn build(self) -> WorkOs {
        let client = reqwest::Client::builder()
            .user_agent(concat!("workos-rust/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap();

        WorkOs {
            base_url: self.base_url,
            key: self.key.to_owned(),
            client,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_supports_setting_the_base_url_through_the_builder() {
        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url("https://auth.your-app.com")
            .unwrap()
            .build();

        assert_eq!(
            workos.base_url(),
            &Url::parse("https://auth.your-app.com").unwrap()
        )
    }

    #[test]
    fn it_supports_setting_the_api_key_through_the_builder() {
        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .key(&ApiKey::from("sk_another_api_key"))
            .build();

        assert_eq!(workos.key(), &ApiKey::from("sk_another_api_key"))
    }

    #[tokio::test]
    async fn it_sets_the_user_agent_header_on_the_client() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/health")
            .match_header(
                "User-Agent",
                concat!("workos-rust/", env!("CARGO_PKG_VERSION")),
            )
            .with_status(200)
            .with_body("User-Agent correctly set")
            .create_async()
            .await;

        let url = workos.base_url().join("/health").unwrap();
        let response = workos.client().get(url).send().await.unwrap();
        let response_body = response.text().await.unwrap();

        assert_eq!(response_body, "User-Agent correctly set")
    }
}
