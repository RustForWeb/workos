use serde::{Deserialize, Serialize};

/// An unpaginated list of records.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnpaginatedList<T> {
    /// The list of items
    pub data: Vec<T>,
}
