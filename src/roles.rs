//! A module for interacting with the WorkOS Roles API.
//!
//! [WorkOS Docs: Role-Based Access Control Guide](https://workos.com/docs/rbac/guide)

mod operations;
mod types;

pub use operations::*;
pub use types::*;

use crate::WorkOs;

/// Roles.
///
/// [WorkOS Docs: Role-Based Access Control Guide](https://workos.com/docs/rbac/guide)
pub struct Roles<'a> {
    workos: &'a WorkOs,
}

impl<'a> Roles<'a> {
    /// Returns a new [`Roles`] instance for the provided WorkOS client.
    pub fn new(workos: &'a WorkOs) -> Self {
        Self { workos }
    }
}
