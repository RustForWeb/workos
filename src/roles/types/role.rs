use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

use crate::Timestamps;

/// The ID of a [`Role`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct RoleId(String);

/// The slug of a [`Role`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct RoleSlug(String);

/// The slug of a [`Role`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSlugObject {
    /// A unique key to reference the role.
    pub slug: String,
}

/// The type of a [`Role`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleType {
    /// An environment role.
    EnvironmentRole,

    /// An organization role.
    OrganizationRole,
}

/// [WorkOS Docs: Role](https://workos.com/docs/reference/roles)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    /// Unique identifier of the role.
    pub id: RoleId,

    /// A descriptive name for the role.
    ///
    /// This field does not need to be unique.
    pub name: String,

    /// A unique key to reference the role.
    pub slug: RoleSlug,

    /// A list of permission slugs assigned to the role.
    pub permissions: Vec<String>,

    /// The type of role.
    pub r#type: RoleType,

    /// The timestamps for the role.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}

/// [WorkOS Docs: Role events](https://workos.com/docs/events/role)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEvent {
    /// A unique key to reference the role.
    pub slug: String,

    /// A list of permission slugs assigned to the role.
    pub permissions: Vec<String>,

    /// The timestamps for the role.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}
