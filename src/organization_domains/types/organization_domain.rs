use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

use crate::{KnownOrUnknown, Timestamps, organizations::OrganizationId};

/// The ID of an [`OrganizationDomain`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct OrganizationDomainId(String);

/// The state of an [`OrganizationDomain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationDomainState {
    /// The organization domain verification is pending.
    Pending,

    /// The organization domain is verified.
    Verified,

    /// The organization domain verification has failed.
    Failed,
}

/// The verification strategy of an [`OrganizationDomain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationDomainVerificationStrategy {
    /// The verification strategy is DNS.
    Dns,

    /// The verification strategy is manual.
    Manual,
}

/// The verification token of an [`OrganizationDomain`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct OrganizationDomainVerificationToken(String);

/// [WorkOS Docs: Organization Domain](https://workos.com/docs/reference/organization-domain)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationDomain {
    /// Unique identifier of the organization domain.
    pub id: OrganizationDomainId,

    /// ID of the parent organization.
    pub organization_id: OrganizationId,

    /// Domain for the organization domain.
    pub domain: String,

    /// Verification state of the domain.
    pub state: KnownOrUnknown<OrganizationDomainState, String>,

    /// Strategy used to verify the domain
    pub verification_strategy: KnownOrUnknown<OrganizationDomainVerificationStrategy, String>,

    /// Validation token to be used in DNS TXT record.
    pub verification_token: Option<OrganizationDomainVerificationToken>,

    /// The timestamps for the organization domain.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}
