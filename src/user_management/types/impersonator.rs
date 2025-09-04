use serde::{Deserialize, Serialize};

/// [WorkOS Docs: Impersonation](https://workos.com/docs/user-management/impersonation)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Impersonator {
    /// The email address of the WorkOS Dashboard user who is impersonating the user
    pub email: String,

    /// The justification the impersonator gave for impersonating the user.
    pub reason: Option<String>,
}
