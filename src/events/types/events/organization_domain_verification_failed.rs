use serde::{Deserialize, Serialize};

use crate::organization_domains::OrganizationDomain;

/// [WorkOS Docs: `organization_domain.verification_failed` event](https://workos.com/docs/events/organization-domain).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationDomainVerificationFailedEvent(pub OrganizationDomain);
