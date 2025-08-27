use thiserror::Error;

/// A JSON or text body.
#[derive(Clone, Debug)]
pub enum JsonOrText {
    /// JSON body.
    Json(serde_json::Value),

    /// Text body.
    Text(String),
}

/// A WorkOS SDK error.
#[derive(Debug, Error)]
pub enum WorkOsError<E> {
    /// An error occurred with the current operation.
    #[error("operational error")]
    Operation(E),

    /// An unauthorized response was received from the WorkOS API.
    #[error("unauthorized")]
    Unauthorized,

    /// An unknown error response was received from the WorkOS API.
    #[error("unknown error")]
    Unknown {
        /// The response status code.
        status: reqwest::StatusCode,

        /// The response body.
        body: JsonOrText,
    },

    /// An error occurred while parsing a URL.
    #[error("URL parse error")]
    UrlParseError(#[from] url::ParseError),

    /// An error occurred while parsing an IP address.
    #[error("IP addres parse error")]
    IpAddrParseError(#[from] std::net::AddrParseError),

    /// An unhandled error occurred with the API request.
    #[error("request error")]
    RequestError(#[from] reqwest::Error),
}

/// A WorkOS SDK result.
pub type WorkOsResult<T, E> = Result<T, WorkOsError<E>>;
