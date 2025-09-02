use std::collections::HashMap;

use derive_more::{Deref, Display, From};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::directory_sync::{DirectoryGroup, DirectoryId};
use crate::organizations::OrganizationId;
use crate::roles::RoleSlugObject;
use crate::{KnownOrUnknown, Timestamps};

/// The ID of a [`DirectoryUser`].
#[derive(
    Clone, Debug, Deref, Display, From, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[from(forward)]
pub struct DirectoryUserId(String);

/// [WorkOS Docs: Directory User](https://workos.com/docs/reference/directory-sync/directory-user)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryUser<TCustomAttributes = HashMap<String, Value>> {
    /// Unique identifier for the Directory User.
    pub id: DirectoryUserId,

    /// Unique identifier for the user, assigned by the Directory Provider.
    ///
    /// Different Directory Providers use different ID formats.
    pub idp_id: String,

    /// The identifier of the Directory the Directory User belongs to.
    pub directory_id: DirectoryId,

    /// The identifier for the Organization in which the Directory resides.
    pub organization_id: Option<OrganizationId>,

    /// The first name of the user.
    pub first_name: Option<String>,

    /// The last name of the user.
    pub last_name: Option<String>,

    /// The emails of the directory user.
    pub emails: Vec<DirectoryUserEmail>,

    /// The groups that the user is a member of.
    pub groups: Vec<DirectoryGroup>,

    /// The state of the user.
    pub state: KnownOrUnknown<DirectoryUserState, String>,

    /// An object containing the custom attribute mapping for the Directory Provider.
    pub custom_attributes: TCustomAttributes,

    /// The role of the user.
    pub role: RoleSlugObject,

    /// The timestamps for the directory user.
    #[serde(flatten)]
    pub timestamps: Timestamps,
}

/// The state of a [`DirectoryUser`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryUserState {
    /// The directory user is active.
    Active,

    /// The directory user is inactive.
    Inactive,

    /// The directory user was suspended from the directory.
    Suspended,
}

/// An email address for a [`DirectoryUser`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryUserEmail {
    /// Whether this is the directory user's primary email address.
    pub primary: Option<bool>,

    /// The type of the email address.
    pub r#type: Option<String>,

    /// The email address.
    pub value: Option<String>,
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use serde::Deserialize;
    use serde_json::{Value, json};

    use crate::directory_sync::{DirectoryGroup, DirectoryGroupId};
    use crate::organizations::OrganizationId;
    use crate::roles::{RoleSlug, RoleSlugObject};
    use crate::{KnownOrUnknown, Timestamp, Timestamps};

    use super::{
        DirectoryId, DirectoryUser, DirectoryUserEmail, DirectoryUserId, DirectoryUserState,
    };

    #[test]
    fn it_deserializes_a_directory_user() {
        let directory_user: DirectoryUser = serde_json::from_str(
            &json!({
                "id": "directory_user_01E1JG7J09H96KYP8HM9B0G5SJ",
                "idp_id": "2836",
                "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                "organization_id": "org_01EZTR6WYX1A0DSE2CYMGXQ24Y",
                "first_name": "Marcelina",
                "last_name": "Davis",
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "marcelina@foo-corp.com"
                    }
                ],
                "groups": [
                    {
                        "id": "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
                        "idp_id": "1",
                        "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                        "name": "Engineering",
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    }
                ],
                "state": "active",
                "created_at": "2021-06-25T19:07:33.155Z",
                "updated_at": "2021-06-25T19:07:33.155Z",
                "custom_attributes": {
                    "department": "Engineering",
                    "job_title": "Software Engineer"
                },
                "role": {
                    "slug": "member"
                }
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(
            directory_user,
            DirectoryUser {
                id: DirectoryUserId::from("directory_user_01E1JG7J09H96KYP8HM9B0G5SJ"),
                idp_id: "2836".to_string(),
                directory_id: DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74"),
                organization_id: Some(OrganizationId::from("org_01EZTR6WYX1A0DSE2CYMGXQ24Y")),
                first_name: Some("Marcelina".to_string()),
                last_name: Some("Davis".to_string()),
                emails: vec![DirectoryUserEmail {
                    primary: Some(true),
                    r#type: Some("work".to_string()),
                    value: Some("marcelina@foo-corp.com".to_string())
                }],
                groups: vec![DirectoryGroup {
                    id: DirectoryGroupId::from("directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT"),
                    idp_id: "1".to_string(),
                    directory_id: DirectoryId::from("directory_01ECAZ4NV9QMV47GW873HDCX74"),
                    organization_id: None,
                    name: "Engineering".to_string(),
                    timestamps: Timestamps {
                        created_at: Timestamp::try_from("2021-06-25T19:07:33.155Z").unwrap(),
                        updated_at: Timestamp::try_from("2021-06-25T19:07:33.155Z").unwrap()
                    }
                }],
                state: KnownOrUnknown::Known(DirectoryUserState::Active),
                custom_attributes: HashMap::from([
                    (
                        "department".to_string(),
                        Value::String("Engineering".to_string())
                    ),
                    (
                        "job_title".to_string(),
                        Value::String("Software Engineer".to_string())
                    )
                ]),
                role: RoleSlugObject {
                    slug: RoleSlug::from("member"),
                },
                timestamps: Timestamps {
                    created_at: Timestamp::try_from("2021-06-25T19:07:33.155Z").unwrap(),
                    updated_at: Timestamp::try_from("2021-06-25T19:07:33.155Z").unwrap(),
                }
            }
        )
    }

    #[test]
    fn it_deserializes_a_directory_user_with_a_provided_custom_attributes_type() {
        #[derive(Debug, PartialEq, Eq, Deserialize)]
        struct MyCustomAttributes {
            pub department: String,
        }

        let directory_user: DirectoryUser<MyCustomAttributes> = serde_json::from_str(
            &json!({
                "id": "directory_user_01E1JG7J09H96KYP8HM9B0G5SJ",
                "idp_id": "2836",
                "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                "first_name": "Marcelina",
                "last_name": "Davis",
                "emails": [
                    {
                        "primary": true,
                        "type": "work",
                        "value": "marcelina@foo-corp.com"
                    }
                ],
                "username": "marcelina@foo-corp.com",
                "groups": [
                    {
                        "id": "directory_group_01E64QTDNS0EGJ0FMCVY9BWGZT",
                        "idp_id": "",
                        "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                        "name": "Engineering",
                        "created_at": "2021-06-25T19:07:33.155Z",
                        "updated_at": "2021-06-25T19:07:33.155Z"
                    }
                ],
                "state": "active",
                "created_at": "2021-06-25T19:07:33.155Z",
                "updated_at": "2021-06-25T19:07:33.155Z",
                "custom_attributes": {
                    "department": "Engineering"
                },
                "role": {
                    "slug": "member"
                }
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(
            directory_user.custom_attributes,
            MyCustomAttributes {
                department: "Engineering".to_string()
            }
        )
    }
}
