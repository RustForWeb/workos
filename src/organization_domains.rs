//! A module for interacting with the WorkOS Organization Domains API.
//!
//! [WorkOS Docs: Domain Verification Guide](https://workos.com/docs/domain-verification/guide)

mod operations;
mod types;

pub use operations::*;
pub use types::*;

use crate::WorkOs;

/// Organization Domains.
///
/// [WorkOS Docs: Domain Verification Guide](https://workos.com/docs/domain-verification/guide)
pub struct OrganizationDomains<'a> {
    workos: &'a WorkOs,
}

impl<'a> OrganizationDomains<'a> {
    /// Returns a new [`OrganizationDomains`] instance for the provided WorkOS client.
    pub fn new(workos: &'a WorkOs) -> Self {
        Self { workos }
    }
}
