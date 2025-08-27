//! A module for interacting with the WorkOS Roles API.
//!
//! [WorkOS Docs: Roles](https://workos.com/docs/roles)

mod operations;
mod types;

pub use operations::*;
pub use types::*;

use crate::WorkOs;

/// Roles.
///
/// [WorkOS Docs: Roles](https://workos.com/docs/roles)
pub struct Roles<'a> {
    workos: &'a WorkOs,
}

impl<'a> Roles<'a> {
    /// Returns a new [`Roles`] instance for the provided WorkOS client.
    pub fn new(workos: &'a WorkOs) -> Self {
        Self { workos }
    }
}
