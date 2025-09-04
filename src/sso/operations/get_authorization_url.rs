use url::{ParseError, Url};

use crate::organizations::OrganizationId;
use crate::sso::{ClientId, ConnectionId, Sso};

/// An OAuth provider to use for Single Sign-On (SSO).
#[derive(Clone, Copy, Debug)]
pub enum Provider {
    /// Sign in with Google OAuth.
    GoogleOauth,

    /// Sign in with Microsoft OAuth.
    MicrosoftOauth,
}

/// The selector to use to determine which connection to use for SSO.
#[derive(Debug)]
pub enum ConnectionSelector<'a> {
    /// Initiate SSO for the connection with the specified ID.
    Connection(&'a ConnectionId),

    /// Initiate SSO for the organization with the specified ID.
    Organization(&'a OrganizationId),

    /// Initiate SSO for the specified OAuth provider.
    Provider(&'a Provider),
}

/// The parameters for [`GetAuthorizationUrl`].
#[derive(Debug)]
pub struct GetAuthorizationUrlParams<'a> {
    /// The client ID for the environment in which SSO is being initiated.
    ///
    /// This value can be obtained from the "Configuration" page in the WorkOS Dashboard.
    pub client_id: &'a ClientId,

    /// The redirect URI the user will be redirected to after successfully signing in.
    pub redirect_uri: &'a str,

    /// The connection selector to use to initiate SSO.
    pub connection_selector: ConnectionSelector<'a>,

    /// The state parameter that will be passed back to the redirect URI.
    pub state: Option<&'a str>,
}

/// [WorkOS Docs: Get Authorization URL](https://workos.com/docs/reference/sso/authorize/get)
pub trait GetAuthorizationUrl {
    /// Returns an authorization URL to use to initiate SSO.
    ///
    /// [WorkOS Docs: Get Authorization URL](https://workos.com/docs/reference/sso/authorize/get)
    ///
    /// # Examples
    ///
    /// ```
    /// # use url::ParseError;
    /// # use workos::sso::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # fn run() -> Result<(), ParseError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let authorization_url = workos
    ///     .sso()
    ///     .get_authorization_url(&GetAuthorizationUrlParams {
    ///         client_id: &ClientId::from("client_123456789"),
    ///         redirect_uri: "https://your-app.com/callback",
    ///         connection_selector: ConnectionSelector::Connection(&ConnectionId::from(
    ///             "conn_01E4ZCR3C56J083X43JQXF3JK5",
    ///         )),
    ///         state: None,
    ///     })?;
    /// # Ok(())
    /// # }
    /// # run().unwrap();
    /// ```
    fn get_authorization_url(&self, params: &GetAuthorizationUrlParams) -> Result<Url, ParseError>;
}

impl GetAuthorizationUrl for Sso<'_> {
    fn get_authorization_url(&self, params: &GetAuthorizationUrlParams) -> Result<Url, ParseError> {
        let GetAuthorizationUrlParams {
            connection_selector,
            client_id,
            redirect_uri,
            state,
        } = params;

        let query = {
            let client_id = client_id.to_string();

            let connection_selector_param = match connection_selector {
                ConnectionSelector::Connection(connection_id) => {
                    ("connection", connection_id.to_string())
                }
                ConnectionSelector::Organization(organization_id) => {
                    ("organization", organization_id.to_string())
                }
                ConnectionSelector::Provider(provider) => (
                    "provider",
                    match provider {
                        Provider::GoogleOauth => "GoogleOAuth".to_string(),
                        Provider::MicrosoftOauth => "MicrosoftOAuth".to_string(),
                    },
                ),
            };

            let redirect_uri = urlencoding::encode(redirect_uri);

            let mut query_params: querystring::QueryParams = vec![
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", &redirect_uri),
                (connection_selector_param.0, &connection_selector_param.1),
            ];

            if let Some(state) = state {
                query_params.push(("state", state));
            }
            String::from(querystring::stringify(query_params).trim_end_matches('&'))
        };

        self.workos
            .base_url()
            .join(&format!("/sso/authorize?{query}"))
    }
}

#[cfg(test)]
mod test {
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[test]
    fn it_builds_an_authorization_url_when_given_a_connection_id() {
        let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));

        let authorization_url = workos
            .sso()
            .get_authorization_url(&GetAuthorizationUrlParams {
                client_id: &ClientId::from("client_123456789"),
                redirect_uri: "https://your-app.com/callback",
                connection_selector: ConnectionSelector::Connection(&ConnectionId::from(
                    "conn_1234",
                )),
                state: None,
            })
            .unwrap();

        assert_eq!(
            authorization_url,
            Url::parse(
                "https://api.workos.com/sso/authorize?response_type=code&client_id=client_123456789&redirect_uri=https%3A%2F%2Fyour-app.com%2Fcallback&connection=conn_1234"
            )
            .unwrap()
        )
    }

    #[test]
    fn it_builds_an_authorization_url_when_given_an_organization_id() {
        let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
        let workos_sso = Sso::new(&workos);

        let authorization_url = workos_sso
            .get_authorization_url(&GetAuthorizationUrlParams {
                client_id: &ClientId::from("client_123456789"),
                redirect_uri: "https://your-app.com/callback",
                connection_selector: ConnectionSelector::Organization(&OrganizationId::from(
                    "org_1234",
                )),
                state: None,
            })
            .unwrap();

        assert_eq!(
            authorization_url,
            Url::parse(
                "https://api.workos.com/sso/authorize?response_type=code&client_id=client_123456789&redirect_uri=https%3A%2F%2Fyour-app.com%2Fcallback&organization=org_1234"
            )
            .unwrap()
        )
    }

    #[test]
    fn it_builds_an_authorization_url_when_given_a_provider() {
        let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
        let workos_sso = Sso::new(&workos);

        let authorization_url = workos_sso
            .get_authorization_url(&GetAuthorizationUrlParams {
                client_id: &ClientId::from("client_123456789"),
                redirect_uri: "https://your-app.com/callback",
                connection_selector: ConnectionSelector::Provider(&Provider::GoogleOauth),
                state: None,
            })
            .unwrap();

        assert_eq!(
            authorization_url,
            Url::parse(
                "https://api.workos.com/sso/authorize?response_type=code&client_id=client_123456789&redirect_uri=https%3A%2F%2Fyour-app.com%2Fcallback&provider=GoogleOAuth"
            )
            .unwrap()
        )
    }
}
