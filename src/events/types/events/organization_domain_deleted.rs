use serde::{Deserialize, Serialize};

use crate::organization_domains::OrganizationDomain;

/// [WorkOS Docs: `organization_domain.deleted` event](https://workos.com/docs/events/organization-domain).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationDomainDeletedEvent(pub OrganizationDomain);
