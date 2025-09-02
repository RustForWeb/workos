use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

use crate::KnownOrUnknown;
use crate::organizations::OrganizationId;

use super::{ConnectionId, ConnectionType};

/// The ID of a [`Profile`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct ProfileId(String);

/// [WorkOS Docs: Profile](https://workos.com/docs/reference/sso/profile)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    /// The ID of the profile.
    pub id: ProfileId,

    /// The ID of the connection to which the profile belongs.
    pub connection_id: ConnectionId,

    /// The ID of the organization in which the connection resides.
    pub organization_id: Option<OrganizationId>,

    /// The type of connection used to authenticate the user.
    pub connection_type: KnownOrUnknown<ConnectionType, String>,

    /// The unique identifier of the user assigned by the Identity Provider.
    pub idp_id: String,

    /// The user's email address.
    pub email: String,

    /// The user's first name.
    pub first_name: Option<String>,

    /// The user's last name.
    pub last_name: Option<String>,
}
