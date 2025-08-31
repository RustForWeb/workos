//! A module for interacting with the WorkOS Widgets API.
//!
//! [WorkOS Docs: Widgets Guide](https://workos.com/docs/authkit/widgets)

mod operations;

pub use operations::*;

use crate::WorkOs;

/// Widgets.
///
/// [WorkOS Docs: Widgets Guide](https://workos.com/docs/authkit/widgets)
pub struct Widgets<'a> {
    workos: &'a WorkOs,
}

impl<'a> Widgets<'a> {
    /// Returns a new [`Widget`] instance for the provided WorkOS client.
    pub fn new(workos: &'a WorkOs) -> Self {
        Self { workos }
    }
}
