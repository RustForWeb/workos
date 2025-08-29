use serde::Serialize;

/// The intent of the Admin Portal.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratePortalLinkIntent {
    /// Launch Admin Portal for creating SSO connections
    Sso,

    /// Launch Admin Portal for creating Directory Sync connections
    #[serde(rename = "dsync")]
    DirectorySync,

    /// Launch Admin Portal for viewing Audit Logs
    AuditLogs,

    /// Launch Admin Portal for creating Log Streams
    LogStreams,

    /// Launch Admin Portal for Domain Verification.
    DomainVerification,

    /// Launch Admin Portal for renewing SAML Certificates.
    CertificateRenewal,
}
