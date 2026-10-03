#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("hub identity does not match the pinned fingerprint")]
    FingerprintMismatch,
    #[error("invalid handshake signature")]
    InvalidSignature,
    #[error("frame too large")]
    FrameTooLarge,
    #[error("frame too short")]
    FrameTooShort,
    #[error("unexpected frame counter (expected {expected}, got {got})")]
    UnexpectedCounter { expected: u64, got: u64 },
    #[error("frame counter exhausted, reconnect to rekey")]
    CounterExhausted,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
}
