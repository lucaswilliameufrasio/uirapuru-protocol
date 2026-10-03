//! Measures the CPU cost of one full handshake (hub + agent side).
use std::time::Instant;

use p256::SecretKey;
use p256::elliptic_curve::rand_core::OsRng;
use uirapuru_protocol::handshake::{ClientHandshake, HubIdentity, accept};

fn main() {
    let hub = HubIdentity::from_secret_key(SecretKey::random(&mut OsRng));
    let pinned = hub.fingerprint();
    let n = 500;
    let (mut hub_ns, mut agent_ns) = (0u128, 0u128);
    for _ in 0..n {
        let t = Instant::now();
        let c = ClientHandshake::new("0.1.0", "h", "linux", "x86_64");
        let hello = c.hello().clone();
        agent_ns += t.elapsed().as_nanos();

        let t = Instant::now();
        let (server_hello, _s) = accept(&hub, &hello).unwrap();
        hub_ns += t.elapsed().as_nanos();

        let t = Instant::now();
        let _ = c.finish(&server_hello, &pinned).unwrap();
        agent_ns += t.elapsed().as_nanos();
    }
    println!(
        "per handshake: hub {:.2} ms, agent {:.2} ms",
        hub_ns as f64 / n as f64 / 1e6,
        agent_ns as f64 / n as f64 / 1e6
    );
}
