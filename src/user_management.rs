//! A module for interacting with the WorkOS User Management API.
//!
//! [WorkOS Docs: User Management](https://workos.com/docs/user-management)

mod cookie_session;
mod operations;
mod types;

pub use cookie_session::*;
pub use operations::*;
pub use types::*;

use crate::WorkOs;

/// User Management.
///
/// [WorkOS Docs: User Management](https://workos.com/docs/user-management)
pub struct UserManagement<'a> {
    workos: &'a WorkOs,
}

impl<'a> UserManagement<'a> {
    /// Returns a new [`UserManagement`] instance for the provided WorkOS client.
    pub fn new(workos: &'a WorkOs) -> Self {
        Self { workos }
    }

    /// Load the session by providing the sealed session and the cookie password.
    pub fn load_sealed_session(
        &'a self,
        client_id: &'a str,
        session_data: &'a str,
        cookie_password: &'a str,
    ) -> CookieSession<'a> {
        CookieSession::new(self, client_id, session_data, cookie_password)
    }
}
