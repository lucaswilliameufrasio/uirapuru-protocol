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
    /// What this machine can build, when it can. Absent on agents that do not
    /// report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildCapacity>,
}

/// Password or token for a registry. Never printed, never stored by the hub's
/// command queue: the hub adds it when it sends the command.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct RegistrySecret(String);

impl RegistrySecret {
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RegistrySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistrySecret(<redacted>)")
    }
}

/// Asks the agent to prove it can use a container registry: log in and push a
/// tiny image, both with a throw-away Docker config so the daemon's own
/// credentials are untouched. The answer is a [`RegistryProbeReport`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryProbe {
    /// Registry host, with the port when it is not the default (`ghcr.io`).
    pub server: String,
    pub username: String,
    pub password: RegistrySecret,
    /// Path inside the registry the proof image goes under (`acme/uirapuru`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_prefix: Option<String>,
}

/// What a [`RegistryProbe`] found.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryProbeReport {
    pub logged_in: bool,
    pub pushed: bool,
    /// Why it stopped, when it did (the registry's own words, never the secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Credential to pull a private image from a registry. The agent logs in with a Docker config
/// of its own for the deploy only; the daemon's credentials are untouched. Added by the hub
/// when it sends the command, never stored with the queued command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryLogin {
    pub server: String,
    pub username: String,
    pub password: RegistrySecret,
}

/// Asks a builder to build an image from a repository and push it to a
/// registry. The answer is a [`BuildImageReport`]; progress goes out as the
/// command's log lines and the build is cancelled with `CancelCommand`.
///
/// The credentials ride the command only: the registry password and the git
/// token are added by the hub when it sends, never stored with the queued
/// command, and the agent keeps them out of arguments, files and logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildImage {
    pub release_id: Uuid,
    /// Git context without credential (`https://host/owner/repo.git#sha:dir`).
    pub context: String,
    /// Dockerfile path inside the context.
    pub dockerfile: String,
    /// Platform to build for (`linux/arm64`).
    pub platform: String,
    /// Where to push, tag included (`ghcr.io/acme/app:abc123`).
    pub image: String,
    pub registry_server: String,
    pub registry_username: String,
    pub registry_password: RegistrySecret,
    /// Lets the build clone a private repository (see [`GitBuildToken`]); the
    /// secret is scoped to this `host[:port]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_token: Option<GitBuildToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_authority: Option<String>,
    /// The operator allowed building with emulation (qemu/binfmt). Without it
    /// the agent refuses to build a foreign platform on a machine that has
    /// emulation registered.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_emulation: bool,
}

/// What a [`BuildImage`] produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildImageReport {
    /// The image as pushed, with its tag.
    pub image: String,
    /// Content digest of the pushed manifest (`sha256:…`).
    pub digest: String,
}

/// What a machine offers as a builder. `platforms` are the platforms it builds
/// natively (e.g. `linux/amd64`). `emulation` says whether binfmt/qemu handlers
/// are registered, so the hub can refuse to schedule a build that would run
/// emulated unless the operator allowed it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildCapacity {
    pub platforms: Vec<String>,
    pub emulation: bool,
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
    /// `com.docker.compose.project.working_dir`: where the stack was started
    /// from (informational; the hub never reads files there).
    #[serde(default)]
    pub compose_workdir: Option<String>,
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

/// One container's usage. CPU is the share of one core over the last sampling
/// window (100.00% = one core, in hundredths of a percent); the other counters
/// are cumulative, so the hub derives rates between samples.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatSample {
    pub container_id: String,
    pub cpu_centi_percent: u32,
    pub mem_bytes: u64,
    pub mem_limit_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub blk_read_bytes: u64,
    pub blk_write_bytes: u64,
    pub pids: u32,
}

/// The server itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostSample {
    /// Busy share of all cores since the previous sample (hundredths of a
    /// percent of the whole machine: 100.00% = every core busy).
    pub cpu_centi_percent: u32,
    pub load1_centi: u32,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stats {
    pub at_ms: i64,
    #[serde(default)]
    pub host: Option<HostSample>,
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

/// Credential the agent hands to the image build so it can clone a private
/// repository. It is passed to `docker compose` as a BuildKit secret read from
/// the process environment, so it is never written to the compose file, the
/// image or `docker inspect`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct GitBuildToken(String);

impl GitBuildToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GitBuildToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GitBuildToken(<redacted>)")
    }
}

/// How the container logs of a service are rotated by Docker (the `json-file` driver): each file
/// is cut at `max_size_mb` and only the newest `max_files` are kept, so a chatty service cannot
/// fill the disk. Sent with the commands that (re)create the service's containers; the agent
/// writes it into the compose override. It replaces any `logging` the compose file has.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogRotation {
    pub max_size_mb: u32,
    pub max_files: u32,
}

/// One kind of thing Docker keeps on the disk, from `docker system df`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskPart {
    pub count: u64,
    pub bytes: u64,
    /// What a cleanup of this kind could give back right now.
    pub reclaimable_bytes: u64,
}

/// The answer to [`CommandKind::DiskUsage`] (the command's result JSON).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskReport {
    pub images: DiskPart,
    pub containers: DiskPart,
    pub volumes: DiskPart,
    pub build_cache: DiskPart,
}

/// Gives back disk space Docker holds on to. Volumes are never touched. Each part is chosen by the
/// hub; the agent does only what is asked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanDisk {
    /// Build cache older than a day.
    #[serde(default)]
    pub build_cache: bool,
    /// Images with no name (left behind when a tag moves to a newer build).
    #[serde(default)]
    pub dangling_images: bool,
    /// Images no container uses, older than this many days, except `keep_images`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unused_images_older_than_days: Option<u32>,
    /// Containers that are not running.
    #[serde(default)]
    pub stopped_containers: bool,
    /// Image references (`name:tag` or an id) that stay whatever their age.
    #[serde(default)]
    pub keep_images: Vec<String>,
}

/// The answer to [`CommandKind::CleanDisk`] (the command's result JSON).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanReport {
    pub removed_images: u32,
    pub removed_containers: u32,
    /// Images, containers and build cache before minus after.
    pub reclaimed_bytes: u64,
}

/// Limits for the build of a deploy that has to build on the machine that
/// runs it (the destination). The agent applies them to a dedicated BuildKit
/// builder, so a build cannot starve the services already running there.
/// Chosen in the hub UI and sent with each command that may build.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildLimits {
    /// Memory the builder may use, in MiB.
    pub memory_mb: u32,
    /// CPU the builder may use, in thousandths of a CPU (1000 = one CPU).
    pub cpu_millis: u32,
    /// The build is refused when the Docker data directory has less free
    /// space than this, in MiB.
    pub min_free_disk_mb: u64,
    /// The build is refused when the machine has less available memory than
    /// this, in MiB.
    pub min_free_memory_mb: u64,
}

/// Name of the environment variable the compose file generated for a build
/// reads the [`GitBuildToken`] from (`secrets: … environment:`). The agent
/// sets it only on the `docker compose` processes of a command.
pub const GIT_BUILD_TOKEN_ENV: &str = "UIRAPURU_GIT_TOKEN";

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
    /// Extra Docker network the service joins (the shared one, so gateways can
    /// reach it by the names in [`crate::naming`]); the agent creates it.
    #[serde(default)]
    pub network: Option<String>,
    /// Names the service answers to on [`Self::network`], besides its own
    /// (stable aliases such as `backend.shop.interno`). Ignored without a network.
    #[serde(default)]
    pub network_aliases: Vec<String>,
    /// Compose project to run under instead of the derived one: an adopted
    /// stack keeps the name it already had, so its volumes and networks are
    /// reused rather than recreated empty.
    #[serde(default)]
    pub project: Option<String>,
    /// Lets the build clone a private repository (see [`GitBuildToken`]).
    /// Minted at dispatch time and never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_git_token: Option<GitBuildToken>,
    /// Limits the build when the deploy builds on this machine (see [`BuildLimits`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_limits: Option<BuildLimits>,
    /// Lets the deploy pull a private image (a build pushed by a builder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_login: Option<RegistryLogin>,
    /// Waits up to this many seconds for every container with a healthcheck to
    /// be healthy before the deploy counts as done (`up --wait`). A blue-green
    /// deploy needs it to know the new slot can take traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_healthy_secs: Option<u32>,
    /// A check the agent makes from outside the container, over the shared
    /// network, after `up`: it works for any image (a distroless one has no
    /// shell or `curl` for a healthcheck inside). Needs `network`; the deploy
    /// fails if the service does not answer within `wait_healthy_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<HttpProbe>,
    /// Replaces the replicas one at a time instead of all at once: for each old
    /// replica the agent starts a new one beside it, waits until it answers
    /// (`probe` or the container healthcheck), and only then stops the old one.
    /// Nothing changes when the service has no replica running yet.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rolling: bool,
    /// Rotates the service's container logs (see [`LogRotation`]); without it the compose file's
    /// own `logging`, or Docker's default, applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_rotation: Option<LogRotation>,
}

/// After a switch, keeps asking the replicas of the new version whether they
/// answer, for `duration_secs`. The result (`result_json`) is
/// `{"verdict": "healthy" | "unhealthy", "reason": "..."}`: `unhealthy` after
/// `max_failures` rounds in a row in which some replica did not answer. A command
/// that fails for any other reason has no verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchService {
    /// The Compose project (slot) that now takes the traffic.
    pub project: String,
    pub service_name: String,
    /// The shared network the replicas are reached on.
    pub network: String,
    pub probe: HttpProbe,
    pub duration_secs: u32,
    pub max_failures: u32,
}

/// `GET <path>` on `<replica>:<port>` until it answers 2xx or 3xx.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpProbe {
    pub port: u16,
    /// Starts with `/`.
    pub path: String,
    /// Pause between attempts.
    pub interval_secs: u32,
    /// Limit for one attempt.
    pub timeout_secs: u32,
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
    #[serde(default)]
    pub network: Option<String>,
    /// Names the service answers to on [`Self::network`], besides its own
    /// (stable aliases such as `backend.shop.interno`). Ignored without a network.
    #[serde(default)]
    pub network_aliases: Vec<String>,
    #[serde(default)]
    pub project: Option<String>,
    /// Rotates the service's container logs (see [`LogRotation`]); without it the compose file's
    /// own `logging`, or Docker's default, applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_rotation: Option<LogRotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StopService {
    /// Compose project override, see [`DeployCompose::project`].
    #[serde(default)]
    pub project: Option<String>,
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
    #[serde(default)]
    pub network: Option<String>,
    /// Names the service answers to on [`Self::network`], besides its own
    /// (stable aliases such as `backend.shop.interno`). Ignored without a network.
    #[serde(default)]
    pub network_aliases: Vec<String>,
    #[serde(default)]
    pub project: Option<String>,
    /// Lets the build clone a private repository (see [`GitBuildToken`]).
    /// Minted at dispatch time and never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_git_token: Option<GitBuildToken>,
    /// Limits the build when the deploy builds on this machine (see [`BuildLimits`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_limits: Option<BuildLimits>,
    /// Rotates the service's container logs (see [`LogRotation`]); without it the compose file's
    /// own `logging`, or Docker's default, applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_rotation: Option<LogRotation>,
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

/// Asks which ports containers have open. The answer is a [`PortsReport`] in the
/// command result's `result_json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPorts {
    /// Container names (`<project>-<service>-<n>`).
    pub containers: Vec<String>,
}

/// Who can reach a listening socket from inside the container's network.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BindScope {
    /// Every interface (`0.0.0.0`, `::`): other containers can connect.
    All,
    /// Only the container itself (`127.0.0.1`, `::1`): a proxy cannot connect.
    Loopback,
    /// One specific address.
    Address,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListeningPort {
    pub port: u16,
    pub address: String,
    pub scope: BindScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerPorts {
    pub name: String,
    /// `false` when the container does not exist or is stopped.
    pub running: bool,
    /// Ports the container declares (compose `ports`/`expose`, the image's `EXPOSE`), TCP.
    pub exposed: Vec<u16>,
    /// TCP sockets in the LISTEN state; `None` when they could not be read.
    pub listening: Option<Vec<ListeningPort>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortsReport {
    pub containers: Vec<ContainerPorts>,
}

/// Asks how existing containers are configured, to write a Compose file for them. The answer is a
/// [`ContainerSpecs`] in the command result's `result_json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InspectContainers {
    /// Container names.
    pub containers: Vec<String>,
}

/// An environment variable of a container. `value` is `None` when the agent judged it a secret
/// (by its name, or because the value carries credentials): such a value never leaves the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// `true` when `value` was withheld as a secret.
    #[serde(default)]
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishedPort {
    /// The host address it is bound to (`0.0.0.0`, `127.0.0.1`...).
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
    /// `tcp`, `udp` or `sctp`.
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MountSpec {
    /// `bind` or `volume` (anything else, such as `tmpfs`, is listed in `unsupported`).
    pub kind: String,
    /// The host path (`bind`) or the volume name (`volume`).
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

/// How an existing container is configured: enough to write a Compose service that recreates it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerSpec {
    pub name: String,
    /// `false` when the container does not exist (nothing else is filled in).
    pub found: bool,
    pub running: bool,
    /// The image reference the container was created from.
    pub image: String,
    /// `no`, `always`, `unless-stopped` or `on-failure`.
    pub restart: String,
    /// The command and entrypoint set on the container, when they differ from the image's.
    pub command: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub env: Vec<EnvEntry>,
    pub ports: Vec<PublishedPort>,
    pub mounts: Vec<MountSpec>,
    /// User-defined networks the container is on (not `bridge`/`host`/`none`).
    pub networks: Vec<String>,
    /// `host`, `none` or `container:...` when the container is not on a normal network.
    pub network_mode: Option<String>,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    /// Settings the generated Compose does NOT carry over (devices, limits, tmpfs, security options...),
    /// each said in a few words, so the review shows what would change.
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerSpecs {
    pub containers: Vec<ContainerSpec>,
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
    /// What Docker holds on the disk (the answer is a [`DiskReport`]).
    DiskUsage,
    CleanDisk(CleanDisk),
    ListPorts(ListPorts),
    /// How existing containers are configured (the answer is a [`ContainerSpecs`]).
    InspectContainers(InspectContainers),
    WatchService(WatchService),
    /// Logs in to a registry and pushes a proof image (the answer is a [`RegistryProbeReport`]).
    RegistryProbe(RegistryProbe),
    /// Builds an image on this machine and pushes it (the answer is a [`BuildImageReport`]).
    BuildImage(Box<BuildImage>),
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
            network: Some("uirapuru".into()),
            network_aliases: vec!["backend.shop.interno".into()],
            project: None,
            build_git_token: Some(GitBuildToken::new("ghs_example")),
            build_limits: None,
            registry_login: None,
            wait_healthy_secs: None,
            probe: None,
            rolling: false,
            log_rotation: Some(LogRotation {
                max_size_mb: 10,
                max_files: 3,
            }),
        }
    }

    #[test]
    fn git_build_token_never_shows_in_debug_and_is_optional_on_the_wire() {
        let with = deploy();
        assert!(!format!("{with:?}").contains("ghs_example"));
        let bytes = rmp_serde::to_vec_named(&with).unwrap();
        assert_eq!(
            rmp_serde::from_slice::<DeployCompose>(&bytes).unwrap(),
            with
        );

        // Without a token the key is not sent, and a peer that never sent it decodes to none.
        let without = DeployCompose {
            build_git_token: None,
            build_limits: None,
            ..deploy()
        };
        let bytes = rmp_serde::to_vec_named(&without).unwrap();
        assert!(!bytes.windows(15).any(|w| w == b"build_git_token"));
        let back: DeployCompose = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.build_git_token, None);
    }

    #[test]
    fn build_limits_are_optional_on_the_wire() {
        let limits = BuildLimits {
            memory_mb: 2048,
            cpu_millis: 1500,
            min_free_disk_mb: 10_240,
            min_free_memory_mb: 512,
        };
        let with = DeployCompose {
            build_limits: Some(limits),
            ..deploy()
        };
        let bytes = rmp_serde::to_vec_named(&with).unwrap();
        assert_eq!(
            rmp_serde::from_slice::<DeployCompose>(&bytes).unwrap(),
            with
        );

        // Without limits the key is not sent, and a peer that never sent it decodes to none.
        let bytes = rmp_serde::to_vec_named(&deploy()).unwrap();
        assert!(!bytes.windows(12).any(|w| w == b"build_limits"));
        let back: DeployCompose = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.build_limits, None);
    }

    #[test]
    fn wait_healthy_is_optional_on_the_wire() {
        let with = DeployCompose {
            wait_healthy_secs: Some(120),
            ..deploy()
        };
        let bytes = rmp_serde::to_vec_named(&with).unwrap();
        assert_eq!(
            rmp_serde::from_slice::<DeployCompose>(&bytes).unwrap(),
            with
        );

        let bytes = rmp_serde::to_vec_named(&deploy()).unwrap();
        assert!(!bytes.windows(17).any(|w| w == b"wait_healthy_secs"));
        let back: DeployCompose = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.wait_healthy_secs, None);
    }

    #[test]
    fn rolling_is_optional_on_the_wire() {
        let with = DeployCompose {
            rolling: true,
            ..deploy()
        };
        let bytes = rmp_serde::to_vec_named(&with).unwrap();
        assert_eq!(
            rmp_serde::from_slice::<DeployCompose>(&bytes).unwrap(),
            with
        );

        let bytes = rmp_serde::to_vec_named(&deploy()).unwrap();
        assert!(!bytes.windows(7).any(|w| w == b"rolling"));
        assert!(
            !rmp_serde::from_slice::<DeployCompose>(&bytes)
                .unwrap()
                .rolling
        );
    }

    #[test]
    fn the_probe_is_optional_on_the_wire() {
        let with = DeployCompose {
            probe: Some(HttpProbe {
                port: 8080,
                path: "/health-check".into(),
                interval_secs: 2,
                timeout_secs: 3,
            }),
            ..deploy()
        };
        let bytes = rmp_serde::to_vec_named(&with).unwrap();
        assert_eq!(
            rmp_serde::from_slice::<DeployCompose>(&bytes).unwrap(),
            with
        );

        let bytes = rmp_serde::to_vec_named(&deploy()).unwrap();
        assert!(!bytes.windows(5).any(|w| w == b"probe"));
        let back: DeployCompose = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.probe, None);
    }

    #[test]
    fn a_watch_command_roundtrips() {
        let watch = CommandKind::WatchService(WatchService {
            project: "uir-a-web".into(),
            service_name: "web".into(),
            network: "uirapuru".into(),
            probe: HttpProbe {
                port: 8080,
                path: "/health-check".into(),
                interval_secs: 2,
                timeout_secs: 3,
            },
            duration_secs: 300,
            max_failures: 3,
        });
        let bytes = rmp_serde::to_vec_named(&watch).unwrap();
        assert_eq!(rmp_serde::from_slice::<CommandKind>(&bytes).unwrap(), watch);
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
                build: Some(BuildCapacity {
                    platforms: vec!["linux/amd64".into()],
                    emulation: false,
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
                    compose_workdir: None,
                }],
            }),
            AgentMessage::ContainerEvent(ContainerEvent {
                container_id: "abc".into(),
                action: "die".into(),
                at_ms: 2,
            }),
            AgentMessage::Stats(Stats {
                at_ms: 3,
                host: Some(HostSample {
                    cpu_centi_percent: 1234,
                    load1_centi: 150,
                    mem_total_bytes: 8,
                    mem_available_bytes: 4,
                    disk_total_bytes: 100,
                    disk_used_bytes: 40,
                    uptime_secs: 99,
                }),
                samples: vec![StatSample {
                    container_id: "abc".into(),
                    cpu_centi_percent: 10,
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
                    network: None,
                    network_aliases: Vec::new(),
                    project: None,
                    build_git_token: None,
                    build_limits: None,
                    log_rotation: None,
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
    fn a_registry_login_is_optional_on_the_wire_and_redacted() {
        let mut d = deploy();
        let bytes = rmp_serde::to_vec_named(&d).unwrap();
        assert!(!bytes.windows(14).any(|w| w == b"registry_login"));
        d.registry_login = Some(RegistryLogin {
            server: "ghcr.io".into(),
            username: "acme".into(),
            password: RegistrySecret::new("ghp_pull"),
        });
        assert!(!format!("{d:?}").contains("ghp_pull"));
        let bytes = rmp_serde::to_vec_named(&d).unwrap();
        assert_eq!(rmp_serde::from_slice::<DeployCompose>(&bytes).unwrap(), d);
    }

    #[test]
    fn a_build_image_keeps_its_secrets_out_of_debug() {
        let build = BuildImage {
            release_id: id(),
            context: "https://github.com/acme/app.git#abc".into(),
            dockerfile: "Dockerfile".into(),
            platform: "linux/arm64".into(),
            image: "ghcr.io/acme/app:abc".into(),
            registry_server: "ghcr.io".into(),
            registry_username: "acme".into(),
            registry_password: RegistrySecret::new("ghp_registry"),
            git_token: Some(GitBuildToken::new("ghs_git")),
            git_authority: Some("github.com".into()),
            allow_emulation: false,
        };
        let shown = format!("{build:?}");
        assert!(!shown.contains("ghp_registry") && !shown.contains("ghs_git"));
        let bytes = rmp_serde::to_vec_named(&build).unwrap();
        assert!(!bytes.windows(15).any(|w| w == b"allow_emulation"));
        assert_eq!(rmp_serde::from_slice::<BuildImage>(&bytes).unwrap(), build);
    }

    #[test]
    fn a_registry_password_is_redacted_in_debug_output() {
        let probe = RegistryProbe {
            server: "ghcr.io".into(),
            username: "acme".into(),
            password: RegistrySecret::new("ghp_example"),
            image_prefix: None,
        };
        assert!(!format!("{probe:?}").contains("ghp_example"));
        assert_eq!(probe.password.expose(), "ghp_example");
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
    fn a_ports_report_survives_a_round_trip() {
        let report = PortsReport {
            containers: vec![ContainerPorts {
                name: "web-1".into(),
                running: true,
                exposed: vec![3000],
                listening: Some(vec![ListeningPort {
                    port: 3000,
                    address: "0.0.0.0".into(),
                    scope: BindScope::All,
                }]),
            }],
        };
        let bytes = crate::encode(&report).unwrap();
        assert_eq!(crate::decode::<PortsReport>(&bytes).unwrap(), report);
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
    fn a_withheld_secret_carries_no_value() {
        let entry = EnvEntry {
            name: "DB_PASSWORD".into(),
            value: None,
            secret: true,
        };
        let bytes = rmp_serde::to_vec_named(&entry).unwrap();
        assert!(!bytes.windows(5).any(|w| w == b"value"));
        assert_eq!(rmp_serde::from_slice::<EnvEntry>(&bytes).unwrap(), entry);
    }

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
                network: None,
                network_aliases: Vec::new(),
                project: None,
                log_rotation: None,
            }),
            CommandKind::StopService(StopService {
                compose_dir: Some("/d".into()),
                container_name: None,
                project: None,
            }),
            CommandKind::Scale(Scale {
                project_name: "p".into(),
                service_name: "s".into(),
                compose_dir: "/d".into(),
                replicas: 2,
                env_plain: BTreeMap::new(),
                secrets: None,
                network: None,
                network_aliases: Vec::new(),
                project: None,
                build_git_token: None,
                build_limits: None,
                log_rotation: None,
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
            CommandKind::DiskUsage,
            CommandKind::CleanDisk(CleanDisk {
                build_cache: true,
                dangling_images: true,
                unused_images_older_than_days: Some(30),
                stopped_containers: false,
                keep_images: vec!["ghcr.io/acme/api:1".into()],
            }),
            CommandKind::ScanUnmanaged,
            CommandKind::ListPorts(ListPorts {
                containers: vec!["uir-a-b-web-1".into()],
            }),
            CommandKind::InspectContainers(InspectContainers {
                containers: vec!["legacy-web".into()],
            }),
            CommandKind::RegistryProbe(RegistryProbe {
                server: "ghcr.io".into(),
                username: "acme".into(),
                password: RegistrySecret::new("ghp_example"),
                image_prefix: Some("acme/uirapuru".into()),
            }),
            CommandKind::BuildImage(Box::new(BuildImage {
                release_id: id(),
                context: "https://github.com/acme/app.git#abc:web".into(),
                dockerfile: "Dockerfile".into(),
                platform: "linux/amd64".into(),
                image: "ghcr.io/acme/app:abc".into(),
                registry_server: "ghcr.io".into(),
                registry_username: "acme".into(),
                registry_password: RegistrySecret::new("ghp_example"),
                git_token: None,
                git_authority: None,
                allow_emulation: true,
            })),
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
