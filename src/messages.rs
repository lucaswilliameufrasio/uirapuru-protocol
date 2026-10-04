//! Message types exchanged over the stream.
//!
//! `ClientHello`/`ServerHello` travel in clear text (they carry no secret).
//! Everything else is an [`AgentMessage`] or [`HubMessage`] sealed by the
//! [`Session`](crate::session::Session). Unknown fields are ignored on decode
//! so new optional fields can be added without bumping the protocol version.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Handshake ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientHello {
    pub proto: u16,
    /// Ephemeral P-256 public key, SEC1 uncompressed.
    pub eph_pub: Vec<u8>,
    pub nonce_c: [u8; 32],
    pub agent_version: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerHello {
    pub proto: u16,
    pub eph_pub: Vec<u8>,
    pub nonce_s: [u8; 32],
    /// Long-term hub identity (SEC1); its SHA-256 must match the pinned fingerprint.
    pub identity_pub: Vec<u8>,
    /// ECDSA P-256 signature (r||s) over the handshake transcript.
    pub sig: Vec<u8>,
}

// ── Auth ────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthCredential {
    /// One-time token from the UI; exchanged for a permanent credential.
    Enroll {
        token: String,
    },
    Agent {
        agent_id: Uuid,
        secret: String,
    },
}

impl fmt::Debug for AuthCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enroll { .. } => f.write_str("AuthCredential::Enroll(<redacted>)"),
            Self::Agent { agent_id, .. } => {
                write!(f, "AuthCredential::Agent({agent_id}, <redacted>)")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Auth {
    pub credential: AuthCredential,
    /// Commands the agent is still executing, so the hub can reconcile.
    #[serde(default)]
    pub resume: Vec<Uuid>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedCredential {
    pub agent_id: Uuid,
    pub secret: String,
}

impl fmt::Debug for IssuedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IssuedCredential({}, <redacted>)", self.agent_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentConfig {
    pub stats_interval_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthOk {
    pub agent_id: Uuid,
    pub config: AgentConfig,
    /// Present only when the agent enrolled with a one-time token.
    pub issued_credential: Option<IssuedCredential>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthErrorCode {
    InvalidCredential,
    Revoked,
    EnrollmentExpired,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthErr {
    pub code: AuthErrorCode,
    pub message: String,
}

// ── Agent → Hub ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resources {
    pub cpus: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateNetwork {
    pub provider: String,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inventory {
    pub docker_version: Option<String>,
    pub compose_version: Option<String>,
    pub resources: Resources,
    pub private_network: Option<PrivateNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub created_ms: i64,
    /// `com.docker.compose.project` label, used for grouping and adoption.
    pub compose_project: Option<String>,
    pub compose_service: Option<String>,
    /// True when the container belongs to a stack deployed by Uirapuru.
    pub managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerSnapshot {
    pub containers: Vec<ContainerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerEvent {
    pub container_id: String,
    pub action: String,
    pub at_ms: i64,
}

/// Cumulative counters; the hub derives rates between samples.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatSample {
    pub container_id: String,
    pub cpu_ns: u64,
    pub mem_bytes: u64,
    pub mem_limit_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub blk_read_bytes: u64,
    pub blk_write_bytes: u64,
    pub pids: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stats {
    pub at_ms: i64,
    pub samples: Vec<StatSample>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogLine {
    pub at_ms: i64,
    pub stream: LogStream,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogChunk {
    pub stream_id: Uuid,
    pub seq: u64,
    pub lines: Vec<LogLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandAck {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandProgress {
    pub id: Uuid,
    pub seq: u64,
    pub stream: LogStream,
    pub text: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandResult {
    pub id: Uuid,
    pub status: CommandStatus,
    pub error: Option<String>,
    /// Command-specific result, JSON encoded.
    pub result_json: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Healthcheck {
    pub service_id: Uuid,
    pub status: HealthStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum AgentMessage {
    Auth(Auth),
    Inventory(Inventory),
    ContainerSnapshot(ContainerSnapshot),
    ContainerEvent(ContainerEvent),
    Stats(Stats),
    LogChunk(LogChunk),
    CommandAck(CommandAck),
    CommandProgress(CommandProgress),
    CommandResult(CommandResult),
    Healthcheck(Healthcheck),
}

// ── Hub → Agent ─────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipheraAccess {
    pub url: String,
    /// Short-lived, read-only, scoped to one project, environment and key prefix.
    pub service_token: String,
    /// Ciphera project id (UUID).
    pub project_id: String,
    pub environment: String,
}

impl fmt::Debug for CipheraAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipheraAccess")
            .field("url", &self.url)
            .field("service_token", &"<redacted>")
            .field("project_id", &self.project_id)
            .field("environment", &self.environment)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    /// Injected as an environment variable.
    Env,
    /// Written as a file on tmpfs (`*_FILE` convention).
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecureVar {
    /// Variable name inside the container.
    pub name: String,
    /// Secret key in Ciphera (includes the service's key prefix).
    pub key: String,
    pub mode: DeliveryMode,
    /// Pin to this Ciphera version (used by rollbacks); `None` = current.
    #[serde(default)]
    pub version: Option<u32>,
}

/// Where the agent fetches `secure` variables from. The values never pass
/// through the hub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretsSpec {
    pub ciphera: CipheraAccess,
    pub vars: Vec<SecureVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeployCompose {
    pub release_id: Uuid,
    pub service_id: Uuid,
    pub project_name: String,
    pub service_name: String,
    pub git_sha: Option<String>,
    pub image: Option<String>,
    pub compose_content: String,
    pub compose_dir: String,
    /// `plain` variables, stored in the hub database.
    #[serde(default)]
    pub env_plain: BTreeMap<String, String>,
    /// `secure` variables fetched by the agent straight from Ciphera.
    #[serde(default)]
    pub secrets: Option<SecretsSpec>,
    pub replicas: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackCompose {
    pub release_id: Uuid,
    pub service_id: Uuid,
    pub project_name: String,
    pub service_name: String,
    pub compose_dir: String,
    #[serde(default)]
    pub env_plain: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: Option<SecretsSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StopService {
    /// Compose stack to bring down (services).
    pub compose_dir: Option<String>,
    /// Standalone container to stop (managed resources).
    pub container_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scale {
    pub project_name: String,
    pub service_name: String,
    pub compose_dir: String,
    pub replicas: u32,
    /// New replicas are created from the compose file, so they need the same
    /// variables as the running ones.
    #[serde(default)]
    pub env_plain: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: Option<SecretsSpec>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerActionKind {
    Start,
    Stop,
    Restart,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerAction {
    pub container_id: String,
    pub action: ContainerActionKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionResource {
    pub resource_id: Uuid,
    /// e.g. `postgres18`. Must not be named `kind`: that is the tag of
    /// [`CommandKind`] and the two would collide on the wire.
    pub resource_type: String,
    pub name: String,
    pub image: String,
    pub container_name: String,
    /// `KEY=VALUE` entries (not secret: they travel in the command).
    pub env: Vec<String>,
    /// Replaces the image's entrypoint (`docker run --entrypoint`); templates
    /// use `sh` to put a secret from the environment into a flag.
    #[serde(default)]
    pub entrypoint: Option<String>,
    /// Arguments after the image. Passed as is, never through a shell by the
    /// agent (a template that needs a secret in a flag uses `sh -c` itself).
    #[serde(default)]
    pub args: Vec<String>,
    /// Named volumes, `name:/absolute/path`. Host paths are refused.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Secrets fetched by the agent straight from Ciphera and given to the
    /// container as environment variables.
    #[serde(default)]
    pub secrets: Option<SecretsSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunBackup {
    pub backup_id: Uuid,
    pub resource_id: Uuid,
    /// e.g. `pg_dump`.
    pub backup_type: String,
    /// Container that holds the data (`resource_<name>`).
    pub container_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PullImage {
    pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommandKind {
    DeployCompose(Box<DeployCompose>),
    RollbackCompose(RollbackCompose),
    StopService(StopService),
    Scale(Scale),
    ContainerAction(ContainerAction),
    ProvisionResource(ProvisionResource),
    RunBackup(RunBackup),
    PullImage(PullImage),
    ScanUnmanaged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Command {
    pub id: Uuid,
    /// Lets the agent deduplicate redeliveries of the same command.
    pub idempotency_key: String,
    pub deadline_ms: Option<i64>,
    pub command: CommandKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CancelCommand {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscribeLogs {
    pub stream_id: Uuid,
    pub container_id: String,
    pub tail: u32,
    pub follow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsubscribeLogs {
    pub stream_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetConfig {
    pub config: AgentConfig,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotateCredential {
    pub new_secret: String,
}

impl fmt::Debug for RotateCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RotateCredential(<redacted>)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HubMessage {
    AuthOk(AuthOk),
    AuthErr(AuthErr),
    Command(Box<Command>),
    CancelCommand(CancelCommand),
    SubscribeLogs(SubscribeLogs),
    UnsubscribeLogs(UnsubscribeLogs),
    SetConfig(SetConfig),
    RotateCredential(RotateCredential),
    Drain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    fn pair() -> (Session, Session) {
        crate::session::test_pair()
    }

    fn id() -> Uuid {
        Uuid::now_v7()
    }

    fn secrets() -> SecretsSpec {
        SecretsSpec {
            ciphera: CipheraAccess {
                url: "https://ciphera.example".into(),
                service_token: "st_super_secret".into(),
                project_id: "3f1c0f0e-0000-0000-0000-000000000001".into(),
                environment: "production".into(),
            },
            vars: vec![
                SecureVar {
                    name: "DATABASE_URL".into(),
                    key: "WEB__DATABASE_URL".into(),
                    mode: DeliveryMode::Env,
                    version: None,
                },
                SecureVar {
                    name: "TLS_KEY".into(),
                    key: "WEB__TLS_KEY".into(),
                    mode: DeliveryMode::File,
                    version: Some(4),
                },
            ],
        }
    }

    fn deploy() -> DeployCompose {
        DeployCompose {
            release_id: id(),
            service_id: id(),
            project_name: "acme/api".into(),
            service_name: "web".into(),
            git_sha: Some("abc123".into()),
            image: Some("ghcr.io/acme/api:1".into()),
            compose_content: "services:\n  web:\n    image: x\n".into(),
            compose_dir: "/opt/uirapuru/services/acme/web".into(),
            env_plain: BTreeMap::from([("LOG_LEVEL".into(), "info".into())]),
            secrets: Some(secrets()),
            replicas: Some(3),
        }
    }

    #[test]
    fn agent_messages_roundtrip() {
        let (mut agent, mut hub) = pair();
        let msgs = vec![
            AgentMessage::Auth(Auth {
                credential: AuthCredential::Agent {
                    agent_id: id(),
                    secret: "s".into(),
                },
                resume: vec![id()],
            }),
            AgentMessage::Inventory(Inventory {
                docker_version: Some("29.4.1".into()),
                compose_version: None,
                resources: Resources {
                    cpus: 4,
                    memory_bytes: 8 << 30,
                    disk_bytes: 100 << 30,
                },
                private_network: Some(PrivateNetwork {
                    provider: "tailscale".into(),
                    ip: Some("100.64.0.1".into()),
                }),
            }),
            AgentMessage::ContainerSnapshot(ContainerSnapshot {
                containers: vec![ContainerInfo {
                    id: "abc".into(),
                    name: "web-1".into(),
                    image: "x".into(),
                    state: "running".into(),
                    status: "Up 2 hours".into(),
                    created_ms: 1,
                    compose_project: Some("acme".into()),
                    compose_service: Some("web".into()),
                    managed: false,
                }],
            }),
            AgentMessage::ContainerEvent(ContainerEvent {
                container_id: "abc".into(),
                action: "die".into(),
                at_ms: 2,
            }),
            AgentMessage::Stats(Stats {
                at_ms: 3,
                samples: vec![StatSample {
                    container_id: "abc".into(),
                    cpu_ns: 10,
                    mem_bytes: 20,
                    mem_limit_bytes: 30,
                    net_rx_bytes: 1,
                    net_tx_bytes: 2,
                    blk_read_bytes: 3,
                    blk_write_bytes: 4,
                    pids: 5,
                }],
            }),
            AgentMessage::LogChunk(LogChunk {
                stream_id: id(),
                seq: 7,
                lines: vec![LogLine {
                    at_ms: 4,
                    stream: LogStream::Stderr,
                    text: "boom".into(),
                }],
            }),
            AgentMessage::CommandAck(CommandAck { id: id() }),
            AgentMessage::CommandProgress(CommandProgress {
                id: id(),
                seq: 1,
                stream: LogStream::Stdout,
                text: "pulling".into(),
            }),
            AgentMessage::CommandResult(CommandResult {
                id: id(),
                status: CommandStatus::Failed,
                error: Some("exit 1".into()),
                result_json: None,
            }),
            AgentMessage::Healthcheck(Healthcheck {
                service_id: id(),
                status: HealthStatus::Healthy,
                detail: None,
            }),
        ];
        for msg in msgs {
            let frame = agent.seal_message(&msg).unwrap();
            let got: AgentMessage = hub.open_message(&frame).unwrap();
            assert_eq!(got, msg);
        }
    }

    #[test]
    fn hub_messages_roundtrip() {
        let (mut agent, mut hub) = pair();
        let msgs = vec![
            HubMessage::AuthOk(AuthOk {
                agent_id: id(),
                config: AgentConfig {
                    stats_interval_secs: 15,
                },
                issued_credential: Some(IssuedCredential {
                    agent_id: id(),
                    secret: "s".into(),
                }),
            }),
            HubMessage::AuthErr(AuthErr {
                code: AuthErrorCode::Revoked,
                message: "revoked".into(),
            }),
            HubMessage::Command(Box::new(Command {
                id: id(),
                idempotency_key: "release-1".into(),
                deadline_ms: Some(10),
                command: CommandKind::DeployCompose(Box::new(deploy())),
            })),
            HubMessage::Command(Box::new(Command {
                id: id(),
                idempotency_key: "scan".into(),
                deadline_ms: None,
                command: CommandKind::ScanUnmanaged,
            })),
            HubMessage::Command(Box::new(Command {
                id: id(),
                idempotency_key: "scale-1".into(),
                deadline_ms: None,
                command: CommandKind::Scale(Scale {
                    project_name: "acme".into(),
                    service_name: "web".into(),
                    compose_dir: "/opt/x".into(),
                    replicas: 3,
                    env_plain: BTreeMap::new(),
                    secrets: Some(secrets()),
                }),
            })),
            HubMessage::CancelCommand(CancelCommand { id: id() }),
            HubMessage::SubscribeLogs(SubscribeLogs {
                stream_id: id(),
                container_id: "abc".into(),
                tail: 100,
                follow: true,
            }),
            HubMessage::UnsubscribeLogs(UnsubscribeLogs { stream_id: id() }),
            HubMessage::SetConfig(SetConfig {
                config: AgentConfig {
                    stats_interval_secs: 30,
                },
            }),
            HubMessage::RotateCredential(RotateCredential {
                new_secret: "n".into(),
            }),
            HubMessage::Drain,
        ];
        for msg in msgs {
            let frame = hub.seal_message(&msg).unwrap();
            let got: HubMessage = agent.open_message(&frame).unwrap();
            assert_eq!(got, msg);
        }
    }

    #[test]
    fn hello_messages_roundtrip_without_secrets_in_the_clear() {
        let hello = ClientHello {
            proto: 1,
            eph_pub: vec![4; 65],
            nonce_c: [1; 32],
            agent_version: "0.1.0".into(),
            hostname: "h".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        let bytes = rmp_serde::to_vec_named(&hello).unwrap();
        assert_eq!(rmp_serde::from_slice::<ClientHello>(&bytes).unwrap(), hello);
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let out = format!(
            "{:?} {:?} {:?} {:?} {:?}",
            AuthCredential::Enroll {
                token: "enroll_secret_value".into()
            },
            AuthCredential::Agent {
                agent_id: id(),
                secret: "agent_secret_value".into()
            },
            IssuedCredential {
                agent_id: id(),
                secret: "issued_secret_value".into()
            },
            RotateCredential {
                new_secret: "rotate_secret_value".into()
            },
            deploy().secrets,
        );
        for secret in [
            "enroll_secret_value",
            "agent_secret_value",
            "issued_secret_value",
            "rotate_secret_value",
            "st_super_secret",
        ] {
            assert!(!out.contains(secret), "{secret} leaked in Debug output");
        }
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compatibility() {
        #[derive(Serialize)]
        struct AckV2 {
            t: &'static str,
            id: Uuid,
            new_field: u32,
        }
        let bytes = rmp_serde::to_vec_named(&AckV2 {
            t: "command_ack",
            id: id(),
            new_field: 9,
        })
        .unwrap();
        let got: AgentMessage = rmp_serde::from_slice(&bytes).unwrap();
        assert!(matches!(got, AgentMessage::CommandAck(_)));
    }

    #[test]
    fn rejects_unknown_message_type() {
        #[derive(Serialize)]
        struct Bogus {
            t: &'static str,
        }
        let bytes = rmp_serde::to_vec_named(&Bogus { t: "nope" }).unwrap();
        assert!(rmp_serde::from_slice::<AgentMessage>(&bytes).is_err());
    }

    /// Every command variant must survive the wire. Internally tagged enums
    /// break silently when a payload field reuses the tag name.
    #[test]
    fn every_command_kind_roundtrips() {
        let (mut agent, mut hub) = pair();
        let kinds = vec![
            CommandKind::DeployCompose(Box::new(deploy())),
            CommandKind::RollbackCompose(RollbackCompose {
                release_id: id(),
                service_id: id(),
                project_name: "p".into(),
                service_name: "s".into(),
                compose_dir: "/d".into(),
                env_plain: BTreeMap::from([("A".into(), "1".into())]),
                secrets: Some(secrets()),
            }),
            CommandKind::StopService(StopService {
                compose_dir: Some("/d".into()),
                container_name: None,
            }),
            CommandKind::Scale(Scale {
                project_name: "p".into(),
                service_name: "s".into(),
                compose_dir: "/d".into(),
                replicas: 2,
                env_plain: BTreeMap::new(),
                secrets: None,
            }),
            CommandKind::ContainerAction(ContainerAction {
                container_id: "c".into(),
                action: ContainerActionKind::Remove,
            }),
            CommandKind::ProvisionResource(ProvisionResource {
                resource_id: id(),
                resource_type: "postgres18".into(),
                name: "db".into(),
                image: "postgres:18".into(),
                container_name: "resource_db".into(),
                env: vec!["A=1".into()],
                entrypoint: Some("sh".into()),
                args: vec!["-js".into()],
                volumes: vec!["data:/data".into()],
                secrets: None,
            }),
            CommandKind::RunBackup(RunBackup {
                backup_id: id(),
                resource_id: id(),
                backup_type: "pg_dump".into(),
                container_name: "resource_db".into(),
            }),
            CommandKind::PullImage(PullImage {
                image: "x:1".into(),
            }),
            CommandKind::ScanUnmanaged,
        ];
        for kind in kinds {
            let msg = HubMessage::Command(Box::new(Command {
                id: id(),
                idempotency_key: "k".into(),
                deadline_ms: None,
                command: kind,
            }));
            let frame = hub.seal_message(&msg).unwrap();
            let got: HubMessage = agent.open_message(&frame).unwrap();
            assert_eq!(got, msg);
        }
    }
}
