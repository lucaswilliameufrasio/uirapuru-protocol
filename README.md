# uirapuru-protocol

Wire protocol shared by the Uirapuru hub (`uirapuru-backend`) and agent (`uirapuru-agents`).
Design: `uirapuru-backend/docs/agent-stream-protocol.md`.

- `handshake`: authenticated ECDH (ephemeral P-256 on both sides, hub transcript signed with its identity key, agent verifies against a pinned fingerprint).
- `session`: AES-256-GCM frames with a strict per-direction counter (no replay, reorder or nonce reuse).
- `messages`: MessagePack message types (`AgentMessage`, `HubMessage`, handshake hellos). Secrets are redacted in `Debug`.

Cost of one full handshake (release build, `cargo run --release --example handshake_cost`): ~0.5 ms on the hub, ~0.6 ms on the agent.

```sh
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```
