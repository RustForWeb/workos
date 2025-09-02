use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::events::{Event, EventName, Events};
use crate::organizations::OrganizationId;
use crate::{
    PaginatedList, PaginationParams, ResponseExt, UrlEncodableVec, WorkOsError, WorkOsResult,
};

/// Filter to only return events of particular types.
#[derive(Debug, Serialize)]
pub struct EventFilters(UrlEncodableVec<EventName>);

impl From<Vec<EventName>> for EventFilters {
    fn from(event: Vec<EventName>) -> Self {
        Self(event.into())
    }
}

/// Parameters for the [`ListEvents`] function.
#[derive(Debug, Serialize)]
pub struct ListEventsParams<'a> {
    /// The pagination parameters to use when listing events.
    #[serde(flatten)]
    pub pagination: PaginationParams<'a>,

    /// Filter to only return events of particular types.
    #[serde(rename = "events[]")]
    pub events: EventFilters,

    /// Filter to only return events belonging only to specific Organizations
    ///
    ///  User events (e.g user.created) will not be Organization specific.
    pub organization_id: Option<&'a OrganizationId>,

    /// ISO 8601 formatted date range start for a stream of events.
    ///
    /// Can be provided without range_end to fetch all events since range_start. Mutually exclusive with the after parameter.
    pub range_start: Option<&'a str>,

    /// ISO 8601 formatted date range end for a stream of events.
    pub range_end: Option<&'a str>,
}

/// An error returned from [`ListEvents`].
#[derive(Debug, Error)]
pub enum ListEventsError {}

impl From<ListEventsError> for WorkOsError<ListEventsError> {
    fn from(err: ListEventsError) -> Self {
        Self::Operation(err)
    }
}

/// [WorkOS Docs: List Events](https://workos.com/docs/reference/events/list)
#[async_trait]
pub trait ListEvents {
    /// Get a list of all of events up to 30 days old.
    ///
    /// [WorkOS Docs: List Events](https://workos.com/docs/reference/events/list)
    ///
    /// # Examples
    ///
    /// ```
    /// # use workos::WorkOsResult;
    /// # use workos::events::*;
    /// use workos::{ApiKey, WorkOs};
    ///
    /// # async fn run() -> WorkOsResult<(), ()> {
    /// let workos = WorkOs::new(&ApiKey::from("sk_example_123456789"));
    ///
    /// let paginated_events = workos
    ///     .events()
    ///     .list_events(&ListEventsParams {
    ///         pagination: Default::default(),
    ///         events: vec![EventName::DsyncUserCreated, EventName::DsyncUserUpdated, EventName::DsyncUserDeleted].into(),
    ///         organization_id: None,
    ///         range_start: None,
    ///         range_end: None,
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_events(
        &self,
        params: &ListEventsParams<'_>,
    ) -> WorkOsResult<PaginatedList<Event>, ()>;
}

#[async_trait]
impl ListEvents for Events<'_> {
    async fn list_events(
        &self,
        params: &ListEventsParams<'_>,
    ) -> WorkOsResult<PaginatedList<Event>, ()> {
        let url = self.workos.base_url().join("/events")?;
        let events = self
            .workos
            .client()
            .get(url)
            .query(&params)
            .bearer_auth(self.workos.key())
            .send()
            .await?
            .handle_unauthorized_or_generic_error()
            .await?
            .json::<PaginatedList<Event>>()
            .await?;

        Ok(events)
    }
}

#[cfg(test)]
mod test {
    use mockito::Matcher;
    use serde_json::json;
    use tokio;

    use crate::events::EventId;
    use crate::{ApiKey, WorkOs};

    use super::*;

    #[tokio::test]
    async fn it_calls_the_list_events_endpoint() {
        let mut server = mockito::Server::new_async().await;

        let workos = WorkOs::builder(&ApiKey::from("sk_example_123456789"))
            .base_url(&server.url())
            .unwrap()
            .build();

        server
            .mock("GET", "/events")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("order".to_string(), "desc".to_string()),
                Matcher::UrlEncoded(
                    "events[]".to_string(),
                    "dsync.user.created,dsync.user.updated,dsync.user.deleted".to_string(),
                ),
            ]))
            .match_header("Authorization", "Bearer sk_example_123456789")
            .with_status(200)
            .with_body(
                json!({
                    "object": "list",
                    "data": [
                        {
                        "object": "event",
                        "id": "event_01H2GNQD5D7ZE06FDDS75NFPHY",
                        "event": "dsync.group.user_added",
                        "data": {
                            "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                            "user": {
                                "id": "directory_user_01E1X56GH84T3FB41SD6PZGDBX",
                                "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                                "organization_id": "org_01EZTR6WYX1A0DSE2CYMGXQ24Y",
                                "idp_id": "2936",
                                "emails": [
                                    {
                                        "primary": true,
                                        "type": "work",
                                        "value": "eric@example.com"
                                    }
                                ],
                                "groups": [
                                    {
                                        "id": "directory_group_01E1X5GPMMXF4T1DCERMVEEPVW",
                                        "idp_id": "02grqrue4294w24",
                                        "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                                        "organization_id": "org_01EZTR6WYX1A0DSE2CYMGXQ24Y",
                                        "name": "Developers",
                                        "created_at": "2021-06-25T19:07:33.155Z",
                                        "updated_at": "2021-06-25T19:07:33.155Z",
                                    }
                                ],
                                "first_name": "Eric",
                                "last_name": "Schneider",
                                "email": "eric@example.com",
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
                            },
                            "group": {
                                "id": "directory_group_01E1X5GPMMXF4T1DCERMVEEPVW",
                                "idp_id": "02grqrue4294w24",
                                "directory_id": "directory_01ECAZ4NV9QMV47GW873HDCX74",
                                "organization_id": "org_01EZTR6WYX1A0DSE2CYMGXQ24Y",
                                "name": "Developers",
                                "created_at": "2021-06-25T19:07:33.155Z",
                                "updated_at": "2021-06-25T19:07:33.155Z"
                            }
                        },
                        "created_at": "2023-06-09T18:12:01.837Z"
                        }
                    ],
                    "list_metadata": {
                        "after": "event_01H2GQNMQNH8VRXVR7AEYG9XCJ"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let paginated_list = workos
            .events()
            .list_events(&ListEventsParams {
                pagination: Default::default(),
                events: vec![
                    EventName::DsyncUserCreated,
                    EventName::DsyncUserUpdated,
                    EventName::DsyncUserDeleted,
                ]
                .into(),
                organization_id: None,
                range_start: None,
                range_end: None,
            })
            .await
            .unwrap();

        assert_eq!(
            paginated_list.data.into_iter().next().map(|event| event.id),
            Some(EventId::from("event_01H2GNQD5D7ZE06FDDS75NFPHY"))
        )
    }
}
