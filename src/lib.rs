//! Rust SDK for interacting with the [WorkOS](https://workos.com) API.
//!
//! # WARNING: Crate moved
//!
//! This crate has moved to [`workos`](https://crates.io/crates/workos). Please upgrade by changing the crate name in `Cargo.toml`:
//!
//! ```diff
//! - workos-sdk = "0.4.1"
//! + workos = "0.5.0"
//! ```

#![warn(missing_docs)]

mod core;
mod known_or_unknown;
mod workos;

pub mod admin_portal;
pub mod directory_sync;
pub mod events;
pub mod mfa;
pub mod organizations;
pub mod passwordless;
pub mod roles;
pub mod sso;
pub mod user_management;

pub use crate::core::*;
pub use crate::workos::*;
pub use known_or_unknown::*;
