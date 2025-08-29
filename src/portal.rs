//! A module for interacting with the WorkOS Admin Portal.
//!
//! [WorkOS Docs: Admin Portal Guide](https://workos.com/docs/admin-portal/guide)

mod operations;
mod types;

pub use operations::*;
pub use types::*;

use crate::WorkOs;

/// Admin Portal.
///
/// [WorkOS Docs: Admin Portal Guide](https://workos.com/docs/admin-portal/guide)
pub struct Portal<'a> {
    workos: &'a WorkOs,
}

impl<'a> Portal<'a> {
    /// Returns a new [`AdminPortal`] instance for the provided WorkOS client.
    pub fn new(workos: &'a WorkOs) -> Self {
        Self { workos }
    }
}
