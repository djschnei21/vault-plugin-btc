use crate::proto::pb;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("wallet not found: {0}")]
    WalletNotFound(String),

    #[error("wallet already exists: {0}")]
    WalletAlreadyExists(String),

    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("invalid descriptor: {0}")]
    InvalidDescriptor(String),

    #[error("signing error: {0}")]
    SigningError(String),

    #[error("invalid PSBT: {0}")]
    InvalidPsbt(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("unsupported path: {0}")]
    UnsupportedPath(String),

    #[error("unsupported operation: {0} on {1}")]
    UnsupportedOperation(String, String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("broker error: {0}")]
    Broker(String),

    #[error("not configured: {0}")]
    NotConfigured(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Convert to a Vault ProtoError for gRPC responses.
    pub fn to_proto_error(&self) -> pb::ProtoError {
        let (err_type, code) = match self {
            Error::WalletNotFound(_) => (7, 404),        // ErrTypeInvalidRequest
            Error::WalletAlreadyExists(_) => (7, 400),   // ErrTypeInvalidRequest
            Error::InvalidMnemonic(_) => (7, 400),
            Error::InvalidDescriptor(_) => (7, 400),
            Error::InvalidPsbt(_) => (7, 400),
            Error::InvalidRequest(_) => (7, 400),
            Error::UnsupportedPath(_) => (6, 404),       // ErrTypeUnsupportedPath
            Error::UnsupportedOperation(_, _) => (5, 405), // ErrTypeUnsupportedOperation
            Error::NotConfigured(_) => (7, 400),
            Error::Storage(_) => (2, 500),               // ErrTypeInternalError
            Error::Broker(_) => (2, 500),
            Error::Internal(_) => (2, 500),
            Error::Serde(_) => (2, 500),
            Error::SigningError(_) => (2, 500),
            Error::ConfigError(_) => (7, 400),
        };
        pb::ProtoError {
            err_type,
            err_msg: self.to_string(),
            err_code: code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_to_proto_error() {
        let err = Error::WalletNotFound("test".to_string());
        let proto = err.to_proto_error();
        assert_eq!(proto.err_code, 404);
        assert!(proto.err_msg.contains("test"));

        let err = Error::InvalidRequest("bad input".to_string());
        let proto = err.to_proto_error();
        assert_eq!(proto.err_code, 400);

        let err = Error::UnsupportedPath("/foo".to_string());
        let proto = err.to_proto_error();
        assert_eq!(proto.err_code, 404);

        let err = Error::Storage("connection failed".to_string());
        let proto = err.to_proto_error();
        assert_eq!(proto.err_code, 500);
    }
}
