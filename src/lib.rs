//! Wire protocol shared by the Uirapuru hub and agent.
//!
//! See `uirapuru-backend/docs/agent-stream-protocol.md` for the design.

pub mod enrollment;
pub mod error;
pub mod handshake;
pub mod messages;
pub mod session;

pub use error::ProtocolError;

/// Protocol version carried in the hello messages.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum size of a single encrypted frame on the wire.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
