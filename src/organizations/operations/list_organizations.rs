use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::organizations::{Organization, Organizations};
use crate::{
    PaginatedList, PaginationParams, ResponseExt, UrlEncodableVec, WorkOsError, WorkOsResult,
};

/// The domains to filter the organizations by.
#[derive(Debug, Serialize)]
pub struct DomainFilters<'a>(UrlEncodableVec<&'a str>);

impl<'a> From<Vec<&'a str>> for DomainFilters<'a> {
    fn from(domains: Vec<&'a str>) -> Self {
        Self(domains.into())
    }
}

/// Parameters for the [`ListOrganizations`] function.
#[derive(Debug, Default, Serialize)]
pub struct ListOrganizationsParams<'a> {
    /// The pagination parameters to use when listing organizations.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,

    /// The domains of Organizations to be listed.
    #[serde(rename = "domains[]")]
    pub domains: Option<DomainFilters<'a>>,
}

/// An error returned from [`ListOrganizations`].
#[derive(Debug, Error)]
pub enum ListOrganizationsError {}

impl From<ListOrganizationsError> for WorkOsError<ListOrganizationsError> {
    fn from(err: ListOrganizationsError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List Organizations](https://workos.com/docs/reference/organization/list)
#[async_trait]
pub trait ListOrganizations {
    /// Retrieves a list of [`Organization`]s.
    ///
    /// [WorkOS Docs: List Organizations](https://workos.com/docs/reference/organization/list)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::organizations::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ()> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let paginated_organizations = workos
    ///     .organizations()
    ///     .list_organizations(&ListOrganizationsParams {
    ///         domains: Some(vec!["foo-corp.com"].into()),
    ///         ..Default::default()
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_organizations(
        &self,
        params: &ListOrganizationsParams<'_>,
    ) -> WorkOsResult<PaginatedList<Organization>, ()>;
}

#[async_trait]
impl ListOrganizations for Organizations<'_> {
    async fn list_organizations(
        &self,
        params: &ListOrganizationsParams<'_>,
    ) -> WorkOsResult<PaginatedList<Organization>, ()> {
        let url = self.workos.base_url().join("/organizations")?;
        let organizations = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<Organization>>()
            .await?;

        Ok(organizations)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::organizations::OrganizationId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_list_organizations_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/organizations")
            .match_query(Matcher::UrlEncoded("order".to_string(), "desc".to_string()))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
                      "id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                      "object": "organization",
                      "name": "Foo Corp",
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
                          "created_at": "2021-06-25T19:07:33.155Z",
                          "updated_at": "2021-06-25T19:07:33.155Z",
                        },
                        {
                          "object": "organization_domain",
                          "id": "org_domain_01EHZNS0H9W90A90FV79GAB6AB",
                          "domain": "another-foo-corp-domain.com",
                          "organization_id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                          "state": "verified",
                          "verification_strategy": "dns",
                          "created_at": "2021-06-25T19:07:33.155Z",
                          "updated_at": "2021-06-25T19:07:33.155Z",
                        }
                      ]
                    }
                  ],
                  "list_metadata": {
                    "before": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                    "after": "org_01EJBGJT2PC6638TN5Y380M40Z",
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .organizations()
            .list_organizations(&Default::default())
            .await
            .unwrap();

        assert_eq!(
            paginated_list.metadata.after,
            Some("org_01EJBGJT2PC6638TN5Y380M40Z".to_string())
        )
    }

    #[tokio::test]
    async fn it_calls_the_list_organizations_endpoint_with_the_domain() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/organizations")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".to_string(), "desc".to_string()),
                Matcher::UrlEncoded("domains[]".to_string(), "foo-corp.com".to_string()),
            ]))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                  "data": [
                    {
                      "id": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                      "object": "organization",
                      "name": "Foo Corp",
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
                    }
                  ],
                  "list_metadata": {
                    "before": "org_01EHZNVPK3SFK441A1RGBFSHRT",
                    "after": "org_01EJBGJT2PC6638TN5Y380M40Z",
                  }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .organizations()
            .list_organizations(&ListOrganizationsParams {
                domains: Some(vec!["foo-corp.com"].into()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list
                .data
                .into_iter()
                .next()
                .map(|organization| organization.id),
            Some(OrganizationId::from("org_01EHZNVPK3SFK441A1RGBFSHRT"))
        )
    }
}
