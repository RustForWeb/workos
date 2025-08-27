use async_trait::async_trait;
use thiserror::Error;

use crate::organizations::{Organization, Organizations};
use crate::{ResponseExt, WorkOsError, WorkOsResult};

/// An error returned from [`GetOrganizationByExternalId`].
#[derive(Debug, Error)]
pub enum GetOrganizationByExternalIdError {}

impl From<GetOrganizationByExternalIdError> for WorkOsError<GetOrganizationByExternalIdError> {
    fn from(err: GetOrganizationByExternalIdError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: Get an organization by External ID](https://workos.com/docs/reference/organization/get-by-external-id)
#[async_trait]
pub trait GetOrganizationByExternalId {
    /// et the details of an existing organization by an external identifier.
    ///
    /// [WorkOS Docs: Get an organization by External ID](https://workos.com/docs/reference/organization/get-by-external-id)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organizations::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), GetOrganizationByExternalIdError> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let organization = workos
    ///     .organizations()
    ///     .get_organization_by_external_id("2fe01467-f7ea-4dd2-8b79-c2b4f56d0191")
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn get_organization_by_external_id(
        &self,
        external_id: &str,
    ) -> WorkOsResult<Organization, GetOrganizationByExternalIdError>;
}

#[async_trait]
impl GetOrganizationByExternalId for Organizations<'_> {
    async fn get_organization_by_external_id(
        &self,
        external_id: &str,
    ) -> WorkOsResult<Organization, GetOrganizationByExternalIdError> {
        let external_id = urlencoding::encode(external_id);

        let url = self
            .workos
            .base_url()
            .join(&format!("/organizations/external_id/{external_id}"))?;

        let organization = self
            .workos
            .client()
            .get(url)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<Organization>()
            .await?;

        Ok(organization)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio;

    use crate::{ApiKey, WorkOs, organizations::OrganizationId};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_get_organization_by_external_id_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock(
                "GET",
                "/organizations/external_id/2fe01467-f7ea-4dd2-8b79-c2b4f56d0191",
            )
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                    "object": "organization",
                    "name": "Foo Corporation",
                    "allow_profiles_outside_organization": false,
                    "created_at": "2021-06-25T19:07:33.155Z",
                    "updated_at": "2021-06-25T19:07:33.155Z",
                    "domains": [
                        {
                            "object": "organization_domain",
                            "id": "org_domain_01EHZNVPK2QXHMVWCEDQEKY69A",
                            "domain": "foo-corp.com",
                            "organization_id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                            "state": "verified",
                            "verification_strategy": "dns",
                            "verification_token": "m5Oztg3jdK4NJLgs8uIlIprMw",
                            "created_at": "2021-06-25T19:07:33.155Z",
                            "updated_at": "2021-06-25T19:07:33.155Z"
                        },
                        {
                            "object": "organization_domain",
                            "id": "org_domain_01EHZNS0H9W90A90FV79GAB6AB",
                            "domain": "another-foo-corp-domain.com",
                            "organization_id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                            "state": "verified",
                            "verification_strategy": "dns",
                            "verification_token": "m5Oztg3jdK4NJLgs8uIlIprMw",
                            "created_at": "2021-06-25T19:07:33.155Z",
                            "updated_at": "2021-06-25T19:07:33.155Z"
                        }
                    ]
                })
                .to_string(),
            )
            .create_async()
            .await;

        let organization = workos
            .organizations()
            .get_organization_by_external_id("2fe01467-f7ea-4dd2-8b79-c2b4f56d0191")
            .await
            .unwrap();

        assert_eq!(
            organization.id,
            OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT")
        )
    }
}
