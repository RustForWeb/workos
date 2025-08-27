use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

use crate::{Metadata, Timestamps, organizations::OrganizationDomain};

/// The ID of an [`Organization`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct OrganizationId(String);

/// The ID and name of an [`Organization`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct OrganizationIdAndName {
    /// Unique identifier of the organization.
    pub id: OrganizationId,

    /// A descriptive name for the organization.
    pub name: String,
}

/// [WorkOS Docs: Organization](https://workos.com/docs/reference/organization)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    /// Unique identifier of the organization.
    pub id: OrganizationId,

    /// A descriptive name for the organization.
    pub name: String,

    /// Whether the connections within this organization should allow profiles
    /// that do not have a domain that is present in the set of the organization's
    /// user email domains.
    ///
    /// See [here](https://workos.com/docs/sso/guide/frequently-asked-questions#allow-profiles-outside-organization)
    /// for more details.
    pub allow_profiles_outside_organization: bool,

    /// List of organization domains.
    pub domains: Vec<OrganizationDomain>,

    /// The Strip customer ID associated with this organization.
    pub stripe_customer_id: Option<String>,

    /// The external ID of the organization.
    pub external_id: Option<String>,

    /// Object containing metadata key/value pairs associated with the organization.
    pub metadata: Option<Metadata>,

    /// The timestamps for the organization.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}
