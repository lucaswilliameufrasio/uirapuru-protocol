//! Wire protocol shared by the Uirapuru hub and agent.
//!
//! See `uirapuru-backend/docs/agent-stream-protocol.md` for the design.

pub mod enrollment;
pub mod error;
pub mod handshake;
pub mod messages;
pub mod naming;
pub mod session;

pub use error::ProtocolError;

/// Protocol version carried in the hello messages.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum size of a single encrypted frame on the wire.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Encodes a message (used for the clear-text hello messages).
pub fn encode<T: serde::Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    rmp_serde::to_vec_named(msg).map_err(|e| ProtocolError::Encode(e.to_string()))
}

/// Decodes a message encoded with [`encode`].
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    rmp_serde::from_slice(bytes).map_err(|e| ProtocolError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::ClientHello;

    #[test]
    fn encode_decode_roundtrip_and_rejects_garbage() {
        let hello = ClientHello {
            proto: PROTOCOL_VERSION,
            eph_pub: vec![4; 65],
            nonce_c: [3; 32],
            agent_version: "0.1.0".into(),
            hostname: "h".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        let bytes = encode(&hello).unwrap();
        assert_eq!(decode::<ClientHello>(&bytes).unwrap(), hello);
        assert!(matches!(
            decode::<ClientHello>(&[1, 2, 3]),
            Err(ProtocolError::Decode(_))
        ));
    }
}
