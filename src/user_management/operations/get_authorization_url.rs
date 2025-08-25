use url::{ParseError, Url};

use crate::organizations::OrganizationId;
use crate::sso::{ClientId, ConnectionId};
use crate::user_management::{OauthProvider, UserManagement};

/// Code challenge used for the PKCE flow.
#[derive(Debug)]
pub enum CodeChallenge<'a> {
    /// S256 code challenge method.
    S256(&'a str),
}

/// Which AuthKit screen users should land on upon redirection.
#[derive(Clone, Copy, Debug)]
pub enum ScreenHint {
    /// Sign up screen.
    SignUp,

    /// Sign in screen.
    SignIn,
}

/// An OAuth provider to use for Single Sign-On (SSO) or AuthKit.
#[derive(Clone, Copy, Debug)]
pub enum Provider {
    /// Sign in with AuthKit.
    AuthKit {
        /// Specify which AuthKit screen users should land on upon redirection (
        screen_hint: Option<ScreenHint>,
    },

    /// Sign in with OAuth.
    Oauth(OauthProvider),
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
    /// Identifies the application making the request to the WorkOS server.
    pub client_id: &'a ClientId,

    /// Where to redirect the user after they complete the authentication process.
    pub redirect_uri: &'a str,

    /// The connection selector to use to initiate SSO.
    pub connection_selector: ConnectionSelector<'a>,

    /// An optional parameter that can be used to encode arbitrary information to help restore application state between redirects.
    ///
    /// If included, the redirect URI received from WorkOS will contain the exact state value that was passed.
    pub state: Option<&'a str>,

    /// Code challenge is derived from the code verifier used for the PKCE flow.
    pub code_challenge: Option<CodeChallenge<'a>>,

    /// Can be used to pre-fill the username/email address field of the IdP sign-in page for the user, if you know their username ahead of time.
    pub login_hint: Option<&'a str>,

    /// Can be used to pre-fill the domain field.
    pub domain_hint: Option<&'a str>,
}

/// [WorkOS Docs: Get Authorization URL](https://workos.com/docs/reference/user-management/authentication/get-authorization-url)
pub trait GetAuthorizationUrl {
    /// Generates an OAuth 2.0 authorization URL to authenticate a user with AuthKit or SSO.
    ///
    /// [WorkOS Docs: Get Authorization URL](https://workos.com/docs/reference/user-management/authentication/get-authorization-url)
    ///
    /// # Examples
    ///
    /// ```
    /// # use url::ParseError;
    /// # use workos::sso::{ClientId, ConnectionId};
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # fn run() -> Result<(), ParseError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let authorization_url = workos
    ///     .user_management()
    ///     .get_authorization_url(&GetAuthorizationUrlParams {
    ///         client_id: &ClientId::from("client_123456789"),
    ///         redirect_uri: "https://your-app.com/callback",
    ///         connection_selector: ConnectionSelector::Connection(&ConnectionId::from(
    ///             "conn_01E4ZCR3C56J083X43JQXF3JK5",
    ///         )),
    ///         state: None,
    ///         code_challenge: None,
    ///         login_hint: None,
    ///         domain_hint: None,
    ///     })?;
    /// # Ok(())
    /// # }
    /// # run().unwrap();
    /// ```
    fn get_authorization_url(&self, params: &GetAuthorizationUrlParams) -> Result<Url, ParseError>;
}

impl GetAuthorizationUrl for UserManagement<'_> {
    fn get_authorization_url(&self, params: &GetAuthorizationUrlParams) -> Result<Url, ParseError> {
        let GetAuthorizationUrlParams {
            connection_selector,
            client_id,
            redirect_uri,
            state,
            code_challenge,
            login_hint,
            domain_hint,
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
                        Provider::AuthKit { .. } => "authkit".to_string(),
                        Provider::Oauth(provider) => provider.to_string(),
                    },
                ),
            };

            let mut query_params: querystring::QueryParams = vec![
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", redirect_uri),
                (connection_selector_param.0, &connection_selector_param.1),
            ];

            if let Some(state) = state {
                query_params.push(("state", state));
            }
            if let Some(code_challenge) = code_challenge {
                match code_challenge {
                    CodeChallenge::S256(code_challenge) => {
                        query_params.push(("code_challenge", code_challenge));
                        query_params.push(("code_challenge_method", "S256"));
                    }
                }
            }
            if let Some(login_hint) = login_hint {
                query_params.push(("login_hint", login_hint));
            }
            if let Some(domain_hint) = domain_hint {
                query_params.push(("domain_hint", domain_hint));
            }
            if let ConnectionSelector::Provider(Provider::AuthKit {
                screen_hint: Some(screen_hint),
            }) = connection_selector
            {
                query_params.push((
                    "screen_hint",
                    match screen_hint {
                        ScreenHint::SignUp => "sign-up",
                        ScreenHint::SignIn => "sign-in",
                    },
                ));
            }

            String::from(querystring::stringify(query_params).trim_end_matches('&'))
        };

        self.workos
            .base_url()
            .join(&format!("/user_management/authorize?{query}"))
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
            .user_management()
            .get_authorization_url(&GetAuthorizationUrlParams {
                client_id: &ClientId::from("client_123456789"),
                redirect_uri: "https://your-app.com/callback",
                connection_selector: ConnectionSelector::Connection(&ConnectionId::from(
                    "conn_1234",
                )),
                state: None,
                code_challenge: None,
                login_hint: None,
                domain_hint: None,
            })
            .unwrap();

        assert_eq!(
            authorization_url,
            Url::parse(
                "https://api.workos.com/user_management/authorize?response_type=code&client_id=client_123456789&redirect_uri=https://your-app.com/callback&connection=conn_1234"
            )
            .unwrap()
        )
    }

    #[test]
    fn it_builds_an_authorization_url_when_given_an_organization_id() {
        let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));

        let authorization_url = workos
            .user_management()
            .get_authorization_url(&GetAuthorizationUrlParams {
                client_id: &ClientId::from("client_123456789"),
                redirect_uri: "https://your-app.com/callback",
                connection_selector: ConnectionSelector::Organization(&OrganizationId::from(
                    "org_1234",
                )),
                state: None,
                code_challenge: None,
                login_hint: None,
                domain_hint: None,
            })
            .unwrap();

        assert_eq!(
            authorization_url,
            Url::parse(
                "https://api.workos.com/user_management/authorize?response_type=code&client_id=client_123456789&redirect_uri=https://your-app.com/callback&organization=org_1234"
            )
            .unwrap()
        )
    }

    #[test]
    fn it_builds_an_authorization_url_when_given_a_provider() {
        let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));

        let authorization_url = workos
            .user_management()
            .get_authorization_url(&GetAuthorizationUrlParams {
                client_id: &ClientId::from("client_123456789"),
                redirect_uri: "https://your-app.com/callback",
                connection_selector: ConnectionSelector::Provider(&Provider::Oauth(
                    OauthProvider::GoogleOAuth,
                )),
                state: None,
                code_challenge: None,
                login_hint: None,
                domain_hint: None,
            })
            .unwrap();

        assert_eq!(
            authorization_url,
            Url::parse(
                "https://api.workos.com/user_management/authorize?response_type=code&client_id=client_123456789&redirect_uri=https://your-app.com/callback&provider=GoogleOAuth"
            )
            .unwrap()
        )
    }

    #[test]
    fn it_builds_an_authorization_url_when_given_authkit_provider() {
        let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));

        let authorization_url = workos
            .user_management()
            .get_authorization_url(&GetAuthorizationUrlParams {
                client_id: &ClientId::from("client_123456789"),
                redirect_uri: "https://your-app.com/callback",
                connection_selector: ConnectionSelector::Provider(&Provider::AuthKit {
                    screen_hint: Some(ScreenHint::SignIn),
                }),
                state: None,
                code_challenge: None,
                login_hint: None,
                domain_hint: None,
            })
            .unwrap();

        assert_eq!(
            authorization_url,
            Url::parse(
                "https://api.workos.com/user_management/authorize?response_type=code&client_id=client_123456789&redirect_uri=https://your-app.com/callback&provider=authkit&screen_hint=sign-in"
            )
            .unwrap()
        )
    }
}
