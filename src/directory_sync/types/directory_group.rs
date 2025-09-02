use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};

use crate::Timestamps;
use crate::directory_sync::DirectoryId;
use crate::organizations::OrganizationId;

/// The ID of a [`DirectoryGroup`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct DirectoryGroupId(String);

/// [WorkOS Docs: Directory Group](https://workos.com/docs/reference/directory-sync/directory-group)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryGroup {
    /// Unique identifier for the Directory Group.
    pub id: DirectoryGroupId,

    /// Unique identifier for the group, assigned by the Directory Provider.
    ///
    /// Different Directory Providers use different ID formats.
    pub idp_id: String,

    /// The identifier of the Directory the Directory Group belongs to.
    pub directory_id: DirectoryId,

    /// The identifier for the Organization in which the Directory resides.
    pub organization_id: Option<OrganizationId>,

    /// The name of the Directory Group.
    pub name: String,

    /// The timestamps for the Directory Group.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::organizations::OrganizationId;
    use crate::{Timestamp, Timestamps};

    use super::{DirectoryGroup, DirectoryGroupId, DirectoryId};

    #[test]
    fn it_deserializes_a_directory_group() {
        let directory_group: DirectoryGroup = serde_json::from_str(
            &json!({
                "id": "directory_group_01E1JJS84MFPPQ3G655FHTKX6Z",
                "idp_id": "02grqrue4294w24",
                "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                "organization_id": "org_01EZTR6WYX1A0DSE2CYMGXQ24Y",
                "name": "Developers",
                "created_at": "2021-06-25T19:07:33.155Z",
                "updated_at": "2021-06-25T19:07:33.155Z"
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(
            directory_group,
            DirectoryGroup {
                id: DirectoryGroupId::from("directory_group_01E1JJS84MFPPQ3G655FHTKX6Z"),
                idp_id: "02grqrue4294w24".to_string(),
                directory_id: DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74"),
                organization_id: Some(OrganizationId::from("org_01EZTR6WYX1A0DSE2CYMGXQ24Y")),
                name: "Developers".to_string(),
                timestamps: Timestamps {
                    created_at: Timestamp::try_from("2021-06-25T19:07:33.155Z").unwrap(),
                    updated_at: Timestamp::try_from("2021-06-25T19:07:33.155Z").unwrap(),
                },
            }
        )
    }
}
