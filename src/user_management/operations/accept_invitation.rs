use async_trait::async_trait;
use thiserror::Error;

use crate::user_management::{Invitation, InvitationId, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`AcceptInvitation`].
#[derive(Debug, Error)]
pub enum AcceptInvitationError {}

impl From<AcceptInvitationError> for WorkOsError<AcceptInvitationError> {
    fn from(err: AcceptInvitationError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Accept an invitation](https://workos.com/docs/reference/user-management/invitation/accept)
#[async_trait]
pub trait AcceptInvitation {
    /// Accepts an invitation and, if linked to an organization, activates the user's membership in that organization.
    ///
    /// [WorkOS Docs: Accept an invitation](https://workos.com/docs/reference/user-management/invitation/accept)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), AcceptInvitationError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let invitation = workos
    ///     .user_management()
    ///     .accept_invitation(&InvitationId::from("invitation_01E4ZCR3C56J083X43JQXF3JK5"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn accept_invitation(
        &self,
        invitation_id: &InvitationId,
    ) -> WorkOsResult<Invitation, AcceptInvitationError>;
}

#[async_trait]
impl AcceptInvitation for UserManagement<'_> {
    async fn accept_invitation(
        &self,
        invitation_id: &InvitationId,
    ) -> WorkOsResult<Invitation, AcceptInvitationError> {
        let url = self.workos.base_url().join(&format!(
            "/user_management/invitations/{invitation_id}/accept"
        ))?;
        let user = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<Invitation>()
            .await?;

        Ok(user)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::user_management::InvitationId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_accept_invitation_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/invitations/invitation_01E4ZCR3C56J083X43JQXF3JK5/accept")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "object": "invitation",
                    "id": "invitation_01E4ZCR3C56J083X43JQXF3JK5",
                    "email": "marcelina.davis@example.com",
                    "state": "accepted",
                    "accepted_at": "2021-06-27T19:07:33.155Z",
                    "revoked_at": null,
                    "expires_at": "2021-07-01T19:07:33.155Z",
                    "token": "Z1uX3RbwcIl5fIGJJJCXXisdI",
                    "accept_invitation_url": "https://your-app.com/invite?invitation_token=Z1uX3RbwcIl5fIGJJJCXXisdI",
                    "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                    "inviter_user_id": "user_01HYGBX8ZGD19949T3BM4FW1C3",
                    "accepted_user_id": "user_01JBJDMMV04RSWPG30MQE8ADFV",
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let invitation = workos
            .user_management()
            .accept_invitation(&InvitationId::from("invitation_01E4ZCR3C56J083X43JQXF3JK5"))
            .await
            .unwrap();

        assert_eq!(
            invitation.id,
            InvitationId::from("invitation_01E4ZCR3C56J083X43JQXF3JK5")
        );
        assert!(invitation.accepted_at.is_some());
    }
}
