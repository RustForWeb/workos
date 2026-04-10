use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::user_management::{Invitation, InvitationId, Locale, UserManagement};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// The parameters for [`ResendInvitation`].
#[derive(Debug, Serialize)]
pub struct ResendInvitationParams<'a> {
    /// The ID of the invitation.
    #[serde(skip_serializing)]
    pub invitation_id: &'a InvitationId,

    /// The locale to use when rendering the invitation email.
    pub locale: Option<&'a Locale>,
}

/// An error returned from [`ResendInvitation`].
#[derive(Debug, Error)]
pub enum ResendInvitationError {}

impl From<ResendInvitationError> for WorkOsError<ResendInvitationError> {
    fn from(err: ResendInvitationError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Resend an invitation](https://workos.com/docs/reference/user-management/invitation/resend)
#[async_trait]
pub trait ResendInvitation {
    /// Resends an invitation email to the recipient. The invitation must be in a pending state.
    ///
    /// [WorkOS Docs: Resend an invitation](https://workos.com/docs/reference/user-management/invitation/resend)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::user_management::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ResendInvitationError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let invitation = workos
    ///     .user_management()
    ///     .resend_invitation(&ResendInvitationParams {
    ///         invitation_id: &InvitationId::from("invitation_01E4ZCR3C56J083X43JQXF3JK5"),
    ///         locale: None,
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn resend_invitation(
        &self,
        params: &ResendInvitationParams<'_>,
    ) -> WorkOsResult<Invitation, ResendInvitationError>;
}

#[async_trait]
impl ResendInvitation for UserManagement<'_> {
    async fn resend_invitation(
        &self,
        params: &ResendInvitationParams<'_>,
    ) -> WorkOsResult<Invitation, ResendInvitationError> {
        let url = self.workos.base_url().join(&format!(
            "/user_management/invitations/{id}/resend",
            id = params.invitation_id
        ))?;
        let invitation = self
            .workos
            .client()
            .post(url)
            .bearer_auth(self.workos.key())
            .json(&params)
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<Invitation>()
            .await?;

        Ok(invitation)
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
    async fn it_calls_the_resend_invitation_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("POST", "/user_management/invitations/invitation_01E4ZCR3C56J083X43JQXF3JK5/resend")
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "object": "invitation",
                    "id": "invitation_01E4ZCR3C56J083X43JQXF3JK5",
                    "email": "marcelina.davis@example.com",
                    "state": "pending",
                    "accepted_at": null,
                    "revoked_at": null,
                    "expires_at": "2021-07-01T19:07:33.155Z",
                    "token": "Z1uX3RbwcIl5fIGJJJCXXisdI",
                    "accept_invitation_url": "https://your-app.com/invite?invitation_token=Z1uX3RbwcIl5fIGJJJCXXisdI",
                    "organization_id": "org_01E4ZCR3C56J083X43JQXF3JK5",
                    "inviter_user_id": "user_01HYGBX8ZGD19949T3BM4FW1C3",
                    "accepted_user_id": null,
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let invitation = workos
            .user_management()
            .resend_invitation(&ResendInvitationParams {
                invitation_id: &InvitationId::from("invitation_01E4ZCR3C56J083X43JQXF3JK5"),
                locale: None,
            })
            .await
            .unwrap();

        assert_eq!(
            invitation.id,
            InvitationId::from("invitation_01E4ZCR3C56J083X43JQXF3JK5")
        );
    }
}
