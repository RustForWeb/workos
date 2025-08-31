//! A module for interacting with the WorkOS Organizations API.

mod operations;
mod types;

pub use operations::*;
pub use types::*;

use crate::WorkOs;

/// Organizations.
pub struct Organizations<'a> {
    workos: &'a WorkOs,
}

impl<'a> Organizations<'a> {
    /// Returns a new [`Organizations`] instance for the provided WorkOS client.
    pub fn new(workos: &'a WorkOs) -> Self {
        Self { workos }
    }
}
