use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

use crate::{
    KnownOrUnknown, Timestamps, organizations::OrganizationId, roles::RoleSlugObject,
    user_management::UserId,
};

/// The ID of a [`OrganizationMembership`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct OrganizationMembershipId(String);

/// The status of an [`OrganizationMembership`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationMembershipStatus {
    /// The organization membership is active.
    Active,

    /// The organization membership is inactive.
    Inactive,

    /// The organization membership is pending.
    Pending,
}

/// [WorkOS Docs: Organization membership](https://workos.com/docs/reference/user-management/organization-membership)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMembership {
    /// The unique ID of the organization membership.
    pub id: OrganizationMembershipId,

    /// The ID of the user.
    pub user_id: UserId,

    /// The ID of the organization which the user belongs to.
    pub organization_id: OrganizationId,

    /// The role of the user.
    pub role: RoleSlugObject,

    /// The status of the organization membership.
    pub status: KnownOrUnknown<OrganizationMembershipStatus, String>,

    /// The timestamps for the organization membership.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}
