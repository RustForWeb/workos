use serde::{Deserialize, Serialize};

/// The state of [`DomainData`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainDataState {
    /// Indicate that the organization hasn’t verified ownership of the domain.
    Pending,

    /// Indicate that the organization has confirmed to you that they own this domain
    Verified,
}

/// [WorkOS Docs: Organization Domain](https://workos.com/docs/reference/organization-domain)
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DomainData<'a> {
    /// The domain to be added to the organization.
    pub domain: &'a str,

    /// The verification state of the domain.
    pub state: DomainDataState,
}
