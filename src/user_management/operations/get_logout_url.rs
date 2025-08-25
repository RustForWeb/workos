use url::{ParseError, Url};

use crate::user_management::{SessionId, UserManagement};

/// The parameters for [`GetLogoutUrl`].
#[derive(Debug)]
pub struct GetLogoutUrlParams<'a> {
    /// The ID of the session that is ending. This can be extracted from the sid claim of the access token.
    pub session_id: &'a SessionId,

    /// The location the user's browser should be redirected to by the WorkOS API after the session has been ended.
    pub return_to: Option<&'a Url>,
}

/// [WorkOS Docs: Get logout URL](https://workos.com/docs/reference/user-management/logout/get-logout-url)
pub trait GetLogoutUrl {
    /// Returns a logout URL the user's browser should be redirected to.
    ///
    /// [WorkOS Docs: Get logout URL](https://workos.com/docs/reference/user-management/logout/get-logout-url)
    ///
    /// # Examples
    ///
    /// ```
    /// # use url::{ParseError, Url};
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # fn run() -> Result<(), ParseError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let jwks_url = workos
    ///     .user_management()
    ///     .get_logout_url(&GetLogoutUrlParams {
    ///         session_id: &SessionId::from("session_01HQAG1HENBZMAZD82YRXDFC0B"),
    ///         return_to: Some(&Url::parse("https://your-app.com/signed-out")?)
    ///     })?;
    /// # Ok(())
    /// # }
    /// ```
    fn get_logout_url(&self, params: &GetLogoutUrlParams) -> Result<Url, ParseError>;
}

impl GetLogoutUrl for UserManagement<'_> {
    fn get_logout_url(&self, params: &GetLogoutUrlParams) -> Result<Url, ParseError> {
        let GetLogoutUrlParams {
            session_id,
            return_to,
        } = params;

        let session_id = session_id.to_string();
        let return_to = return_to.map(|return_to| return_to.to_string());

        let query = {
            let mut query_params: querystring::QueryParams = vec![("session_id", &session_id)];

            if let Some(return_to) = &return_to {
                query_params.push(("return_to", return_to));
            }

            String::from(querystring::stringify(query_params).trim_end_matches('&'))
        };

        let url = self
            .workos
            .base_url()
            .join(&format!("/user_management/sessions/logout?{query}"))?;

        Ok(url)
    }
}

#[cfg(test)]
mod test {
    use url::Url;

    use crate::user_management::SessionId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[test]
    fn it_builds_a_logout_url() -> Result<(), ParseError> {
        let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));

        let logout_url = workos
            .user_management()
            .get_logout_url(&GetLogoutUrlParams {
                session_id: &SessionId::from("session_01HQAG1HENBZMAZD82YRXDFC0B"),
                return_to: Some(&Url::parse("https://your-app.com/signed-out")?),
            })
            .unwrap();

        assert_eq!(
            logout_url,
            Url::parse("https://api.workos.com/user_management/sessions/logout?session_id=session_01HQAG1HENBZMAZD82YRXDFC0B&return_to=https://your-app.com/signed-out").unwrap()
        );

        Ok(())
    }
}
