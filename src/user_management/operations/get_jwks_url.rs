use url::{ParseError, Url};

use crate::sso::ClientId;
use crate::user_management::UserManagement;

/// [WorkOS Docs: Get JWKS URL](https://workos.com/docs/reference/user-management/session-tokens/jwks)
pub trait GetJwksUrl {
    /// Returns a URL that hosts the JWKS for signing access tokens.
    ///
    /// [WorkOS Docs: Get JWKS URL](https://workos.com/docs/reference/user-management/session-tokens/jwks)
    ///
    /// # Examples
    ///
    /// ```
    /// # use url::ParseError;
    /// # use workos::sso::ClientId;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # fn run() -> Result<(), ParseError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let jwks_url = workos
    ///     .user_management()
    ///     .get_jwks_url(&ClientId::from("client_123456789"))?;
    /// # Ok(())
    /// # }
    /// ```
    fn get_jwks_url(&self, client_id: &ClientId) -> Result<Url, ParseError>;
}

impl GetJwksUrl for UserManagement<'_> {
    fn get_jwks_url(&self, client_id: &ClientId) -> Result<Url, ParseError> {
        let url = self
            .workos
            .base_url()
            .join("/sso/jwks/")?
            .join(&client_id.to_string())?;

        Ok(url)
    }
}

#[cfg(test)]
mod test {
    use url::Url;

    use crate::sso::ClientId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[test]
    fn it_builds_a_jwks_url() {
        let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));

        let jwks_url = workos
            .user_management()
            .get_jwks_url(&ClientId::from("client_123456789"))
            .unwrap();

        assert_eq!(
            jwks_url,
            Url::parse("https://api.workos.com/sso/jwks/client_123456789").unwrap()
        )
    }
}
