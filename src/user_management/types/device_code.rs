use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

/// A device code that may be exchanged for an access token.
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct DeviceCode(String);
