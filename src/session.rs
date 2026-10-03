//! Encrypted frame layer.
//!
//! Frame = `[8B big-endian counter][AES-256-GCM ciphertext+tag]`.
//! Nonce = `[4B direction][8B counter]`; the counter is also the AAD. The
//! receiver requires the counter to be exactly the expected one (the stream
//! is ordered), which rules out nonce reuse, replay and reordering.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::MAX_FRAME_BYTES;
use crate::error::ProtocolError;

const HEADER_LEN: usize = 8;
const TAG_LEN: usize = 16;
/// Frames allowed per key before the connection must be re-established.
const MAX_FRAMES_PER_KEY: u64 = 1 << 32;

pub struct Session {
    send: Aes256Gcm,
    send_dir: u32,
    send_counter: u64,
    recv: Aes256Gcm,
    recv_dir: u32,
    recv_counter: u64,
}

fn nonce(dir: u32, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&dir.to_be_bytes());
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn cipher(key: [u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(key))
}

impl Session {
    pub(crate) fn new(
        send_key: [u8; 32],
        send_dir: u32,
        recv_key: [u8; 32],
        recv_dir: u32,
    ) -> Self {
        Self {
            send: cipher(send_key),
            send_dir,
            send_counter: 0,
            recv: cipher(recv_key),
            recv_dir,
            recv_counter: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if HEADER_LEN + plaintext.len() + TAG_LEN > MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge);
        }
        if self.send_counter >= MAX_FRAMES_PER_KEY {
            return Err(ProtocolError::CounterExhausted);
        }
        let header = self.send_counter.to_be_bytes();
        let ct = self
            .send
            .encrypt(
                &Nonce::from(nonce(self.send_dir, self.send_counter)),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| ProtocolError::DecryptFailed)?;
        self.send_counter += 1;
        let mut frame = Vec::with_capacity(HEADER_LEN + ct.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&ct);
        Ok(frame)
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge);
        }
        if frame.len() < HEADER_LEN + TAG_LEN {
            return Err(ProtocolError::FrameTooShort);
        }
        let (header, ct) = frame.split_at(HEADER_LEN);
        let got = u64::from_be_bytes(header.try_into().expect("8 bytes"));
        if got != self.recv_counter {
            return Err(ProtocolError::UnexpectedCounter {
                expected: self.recv_counter,
                got,
            });
        }
        let pt = self
            .recv
            .decrypt(
                &Nonce::from(nonce(self.recv_dir, got)),
                Payload {
                    msg: ct,
                    aad: header,
                },
            )
            .map_err(|_| ProtocolError::DecryptFailed)?;
        self.recv_counter += 1;
        Ok(pt)
    }

    /// Serializes `msg` as named-field MessagePack and seals it.
    pub fn seal_message<T: Serialize>(&mut self, msg: &T) -> Result<Vec<u8>, ProtocolError> {
        let bytes =
            rmp_serde::to_vec_named(msg).map_err(|e| ProtocolError::Encode(e.to_string()))?;
        self.seal(&bytes)
    }

    /// Opens a frame and deserializes the MessagePack payload.
    pub fn open_message<T: DeserializeOwned>(&mut self, frame: &[u8]) -> Result<T, ProtocolError> {
        let bytes = self.open(frame)?;
        rmp_serde::from_slice(&bytes).map_err(|e| ProtocolError::Decode(e.to_string()))
    }
}

#[cfg(test)]
pub(crate) fn test_pair() -> (Session, Session) {
    let (a, b) = ([7u8; 32], [9u8; 32]);
    (Session::new(a, 0, b, 1), Session::new(b, 1, a, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        let (a, b) = ([7u8; 32], [9u8; 32]);
        (Session::new(a, 0, b, 1), Session::new(b, 1, a, 0))
    }

    #[test]
    fn roundtrip_in_both_directions() {
        let (mut agent, mut hub) = pair();
        let f = agent.seal(b"hello").unwrap();
        assert_eq!(hub.open(&f).unwrap(), b"hello");
        let f = hub.seal(b"world").unwrap();
        assert_eq!(agent.open(&f).unwrap(), b"world");
    }

    #[test]
    fn rejects_replayed_frame() {
        let (mut agent, mut hub) = pair();
        let f = agent.seal(b"cmd").unwrap();
        hub.open(&f).unwrap();
        assert_eq!(
            hub.open(&f).unwrap_err(),
            ProtocolError::UnexpectedCounter {
                expected: 1,
                got: 0
            }
        );
    }

    #[test]
    fn rejects_reordered_frames() {
        let (mut agent, mut hub) = pair();
        let first = agent.seal(b"1").unwrap();
        let second = agent.seal(b"2").unwrap();
        assert!(matches!(
            hub.open(&second),
            Err(ProtocolError::UnexpectedCounter {
                expected: 0,
                got: 1
            })
        ));
        // The failed attempt must not advance the counter.
        assert_eq!(hub.open(&first).unwrap(), b"1");
        assert_eq!(hub.open(&second).unwrap(), b"2");
    }

    #[test]
    fn rejects_tampered_payload_and_counter() {
        let (mut agent, mut hub) = pair();
        let mut f = agent.seal(b"payload").unwrap();
        *f.last_mut().unwrap() ^= 1;
        assert_eq!(hub.open(&f).unwrap_err(), ProtocolError::DecryptFailed);

        let (mut agent, mut hub) = pair();
        let mut f = agent.seal(b"payload").unwrap();
        f[7] ^= 1; // counter
        assert!(hub.open(&f).is_err());
    }

    #[test]
    fn rejects_frames_from_another_session() {
        let (mut agent, _hub) = pair();
        let (mut agent2, _) = pair();
        let f = agent2.seal(b"x").unwrap();
        // An agent frame cannot be opened by another agent (wrong direction/key).
        assert_eq!(agent.open(&f).unwrap_err(), ProtocolError::DecryptFailed);
    }

    #[test]
    fn rejects_short_and_oversized_frames() {
        let (mut agent, mut hub) = pair();
        assert_eq!(
            hub.open(&[0u8; 5]).unwrap_err(),
            ProtocolError::FrameTooShort
        );
        let big = vec![0u8; MAX_FRAME_BYTES];
        assert_eq!(agent.seal(&big).unwrap_err(), ProtocolError::FrameTooLarge);
        assert_eq!(
            hub.open(&vec![0u8; MAX_FRAME_BYTES + 1]).unwrap_err(),
            ProtocolError::FrameTooLarge
        );
    }

    #[test]
    fn counter_exhaustion_forces_reconnect() {
        let (mut agent, _) = pair();
        agent.send_counter = MAX_FRAMES_PER_KEY;
        assert_eq!(
            agent.seal(b"x").unwrap_err(),
            ProtocolError::CounterExhausted
        );
    }
}
