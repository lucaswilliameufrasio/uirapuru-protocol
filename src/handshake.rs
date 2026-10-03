//! Authenticated key exchange between agent and hub.
//!
//! Both sides use ephemeral P-256 keys (forward secrecy). The hub signs the
//! transcript with its long-term identity key; the agent checks the identity
//! against a fingerprint pinned at enrollment, so the hub is authenticated
//! even without TLS.

use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::pkcs8::DecodePrivateKey;
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::PROTOCOL_VERSION;
use crate::error::ProtocolError;
use crate::messages::{ClientHello, ServerHello};
use crate::session::Session;

/// SHA-256 of a hub identity public key (SEC1 bytes).
pub type Fingerprint = [u8; 32];

pub fn fingerprint(identity_pub: &[u8]) -> Fingerprint {
    Sha256::digest(identity_pub).into()
}

fn transcript(
    proto: u16,
    eph_c: &[u8],
    nonce_c: &[u8; 32],
    eph_s: &[u8],
    nonce_s: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(32 + eph_c.len() + eph_s.len() + 64);
    t.extend_from_slice(b"uirapuru-handshake-v1");
    t.extend_from_slice(&proto.to_be_bytes());
    t.extend_from_slice(eph_c);
    t.extend_from_slice(nonce_c);
    t.extend_from_slice(eph_s);
    t.extend_from_slice(nonce_s);
    t
}

fn derive_session(
    shared: &[u8],
    transcript: &[u8],
    is_client: bool,
) -> Result<Session, ProtocolError> {
    let salt: [u8; 32] = Sha256::digest(transcript).into();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"uirapuru c2s", &mut c2s)
        .map_err(|_| ProtocolError::DecryptFailed)?;
    hk.expand(b"uirapuru s2c", &mut s2c)
        .map_err(|_| ProtocolError::DecryptFailed)?;
    Ok(if is_client {
        Session::new(c2s, 0, s2c, 1)
    } else {
        Session::new(s2c, 1, c2s, 0)
    })
}

fn random_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

fn parse_public(bytes: &[u8]) -> Result<PublicKey, ProtocolError> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| ProtocolError::InvalidPublicKey)
}

/// Long-term hub identity used to sign handshakes.
pub struct HubIdentity {
    signing: SigningKey,
    public: Vec<u8>,
}

impl HubIdentity {
    pub fn from_secret_key(secret: SecretKey) -> Self {
        let public = secret.public_key().to_sec1_bytes().to_vec();
        Self {
            signing: SigningKey::from(secret),
            public,
        }
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, ProtocolError> {
        let secret =
            SecretKey::from_pkcs8_pem(pem).map_err(|_| ProtocolError::InvalidPrivateKey)?;
        Ok(Self::from_secret_key(secret))
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn fingerprint(&self) -> Fingerprint {
        fingerprint(&self.public)
    }
}

/// Hub side: answers a `ClientHello` and derives the session.
pub fn accept(
    identity: &HubIdentity,
    hello: &ClientHello,
) -> Result<(ServerHello, Session), ProtocolError> {
    if hello.proto != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(hello.proto));
    }
    let peer = parse_public(&hello.eph_pub)?;
    let eph = EphemeralSecret::random(&mut OsRng);
    let eph_pub = EncodedPoint::from(PublicKey::from(&eph))
        .as_bytes()
        .to_vec();
    let nonce_s = random_nonce();

    let t = transcript(
        hello.proto,
        &hello.eph_pub,
        &hello.nonce_c,
        &eph_pub,
        &nonce_s,
    );
    let sig: Signature = identity.signing.sign(&t);
    let shared = eph.diffie_hellman(&peer);
    let session = derive_session(shared.raw_secret_bytes(), &t, false)?;

    Ok((
        ServerHello {
            proto: PROTOCOL_VERSION,
            eph_pub,
            nonce_s,
            identity_pub: identity.public.clone(),
            sig: sig.to_bytes().to_vec(),
        },
        session,
    ))
}

/// Agent side: holds the ephemeral key between sending the hello and
/// receiving the `ServerHello`.
pub struct ClientHandshake {
    eph: EphemeralSecret,
    hello: ClientHello,
}

impl ClientHandshake {
    pub fn new(agent_version: &str, hostname: &str, os: &str, arch: &str) -> Self {
        let eph = EphemeralSecret::random(&mut OsRng);
        let eph_pub = EncodedPoint::from(PublicKey::from(&eph))
            .as_bytes()
            .to_vec();
        let hello = ClientHello {
            proto: PROTOCOL_VERSION,
            eph_pub,
            nonce_c: random_nonce(),
            agent_version: agent_version.to_owned(),
            hostname: hostname.to_owned(),
            os: os.to_owned(),
            arch: arch.to_owned(),
        };
        Self { eph, hello }
    }

    pub fn hello(&self) -> &ClientHello {
        &self.hello
    }

    /// Verifies the hub identity against `pinned` and derives the session.
    pub fn finish(
        self,
        server: &ServerHello,
        pinned: &Fingerprint,
    ) -> Result<Session, ProtocolError> {
        if server.proto != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(server.proto));
        }
        if &fingerprint(&server.identity_pub) != pinned {
            return Err(ProtocolError::FingerprintMismatch);
        }
        let verifying = VerifyingKey::from_sec1_bytes(&server.identity_pub)
            .map_err(|_| ProtocolError::InvalidPublicKey)?;
        let sig =
            Signature::from_slice(&server.sig).map_err(|_| ProtocolError::InvalidSignature)?;
        let t = transcript(
            self.hello.proto,
            &self.hello.eph_pub,
            &self.hello.nonce_c,
            &server.eph_pub,
            &server.nonce_s,
        );
        verifying
            .verify(&t, &sig)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        let peer = parse_public(&server.eph_pub)?;
        let shared = self.eph.diffie_hellman(&peer);
        derive_session(shared.raw_secret_bytes(), &t, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> HubIdentity {
        HubIdentity::from_secret_key(SecretKey::random(&mut OsRng))
    }

    fn client() -> ClientHandshake {
        ClientHandshake::new("0.1.0", "host", "linux", "x86_64")
    }

    #[test]
    fn handshake_derives_matching_sessions() {
        let hub = identity();
        let c = client();
        let (server_hello, mut hub_session) = accept(&hub, c.hello()).unwrap();
        let mut agent_session = c.finish(&server_hello, &hub.fingerprint()).unwrap();

        let frame = agent_session.seal(b"ping").unwrap();
        assert_eq!(hub_session.open(&frame).unwrap(), b"ping");
        let frame = hub_session.seal(b"pong").unwrap();
        assert_eq!(agent_session.open(&frame).unwrap(), b"pong");
    }

    #[test]
    fn rejects_hub_with_unpinned_identity() {
        let real = identity();
        let impostor = identity();
        let c = client();
        let (server_hello, _) = accept(&impostor, c.hello()).unwrap();
        let err = c.finish(&server_hello, &real.fingerprint()).err().unwrap();
        assert_eq!(err, ProtocolError::FingerprintMismatch);
    }

    #[test]
    fn rejects_tampered_signature() {
        let hub = identity();
        let c = client();
        let (mut server_hello, _) = accept(&hub, c.hello()).unwrap();
        server_hello.sig[0] ^= 0x01;
        let err = c.finish(&server_hello, &hub.fingerprint()).err().unwrap();
        assert_eq!(err, ProtocolError::InvalidSignature);
    }

    #[test]
    fn rejects_swapped_ephemeral_key() {
        // A man in the middle replacing the hub ephemeral key invalidates the
        // signature because the transcript covers it.
        let hub = identity();
        let c = client();
        let (mut server_hello, _) = accept(&hub, c.hello()).unwrap();
        let other = EncodedPoint::from(PublicKey::from(&EphemeralSecret::random(&mut OsRng)));
        server_hello.eph_pub = other.as_bytes().to_vec();
        let err = c.finish(&server_hello, &hub.fingerprint()).err().unwrap();
        assert_eq!(err, ProtocolError::InvalidSignature);
    }

    #[test]
    fn rejects_unsupported_version() {
        let hub = identity();
        let c = client();
        let mut hello = c.hello().clone();
        hello.proto = 99;
        assert_eq!(
            accept(&hub, &hello).err().unwrap(),
            ProtocolError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn rejects_malformed_client_key() {
        let hub = identity();
        let c = client();
        let mut hello = c.hello().clone();
        hello.eph_pub = vec![1, 2, 3];
        assert_eq!(
            accept(&hub, &hello).err().unwrap(),
            ProtocolError::InvalidPublicKey
        );
    }

    #[test]
    fn each_handshake_yields_distinct_keys() {
        let hub = identity();
        let (c1, c2) = (client(), client());
        let (s1, mut hub1) = accept(&hub, c1.hello()).unwrap();
        let (s2, _) = accept(&hub, c2.hello()).unwrap();
        let _ = c1.finish(&s1, &hub.fingerprint()).unwrap();
        let mut agent2 = c2.finish(&s2, &hub.fingerprint()).unwrap();
        let frame = agent2.seal(b"x").unwrap();
        assert!(hub1.open(&frame).is_err());
    }
}
