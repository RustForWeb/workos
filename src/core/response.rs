use reqwest::{Response, StatusCode};

use crate::{JsonOrText, WorkOsError, WorkOsResult};

pub trait ResponseExt
where
    Self: Sized,
{
    /// Handles an unauthorized error from the WorkOS API by converting it into a
    /// [`WorkOsError::Unauthorized`] response.
    fn handle_unauthorized_error<E>(self) -> WorkOsResult<Self, E>;

    /// Handles a generic error from the WorkOS API by converting it into a
    /// [`WorkOsError::RequestError`] response.
    async fn handle_generic_error<E>(self) -> WorkOsResult<Self, E>;

    /// Handles an unauthorized or generic error from the WorkOS API.
    async fn handle_unauthorized_or_generic_error<E>(self) -> WorkOsResult<Self, E>;
}

impl ResponseExt for Response {
    fn handle_unauthorized_error<E>(self) -> WorkOsResult<Self, E> {
        if self.status() == StatusCode::UNAUTHORIZED {
            Err(WorkOsError::Unauthorized)
        } else {
            Ok(self)
        }
    }

    async fn handle_generic_error<E>(self) -> WorkOsResult<Self, E> {
        let status = self.status();
        if status.is_client_error() || status.is_server_error() {
            if self
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_lowercase().starts_with("application/json"))
            {
                match self.json().await {
                    Ok(value) => Err(WorkOsError::Unknown {
                        status,
                        body: JsonOrText::Json(value),
                    }),
                    Err(err) => Err(WorkOsError::RequestError(err)),
                }
            } else {
                match self.text().await {
                    Ok(text) => Err(WorkOsError::Unknown {
                        status,
                        body: JsonOrText::Text(text),
                    }),
                    Err(err) => Err(WorkOsError::RequestError(err)),
                }
            }
        } else {
            Ok(self)
        }
    }

    async fn handle_unauthorized_or_generic_error<E>(self) -> WorkOsResult<Self, E> {
        self.handle_unauthorized_error()?
            .handle_generic_error()
            .await
    }
}
