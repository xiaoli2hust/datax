mod platform;
pub mod runtime_generation;

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use getrandom::fill as fill_random;
use runtime_generation::RuntimeGeneration;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wait_timeout::ChildExt;
use zeroize::{Zeroize, Zeroizing};

pub use platform::{show_error, show_info};

const PRODUCT_NAME: &str = "DataX Enterprise Studio";
const COMPOSE_PROJECT: &str = "datax-enterprise-studio";
const UI_URL: &str = "http://127.0.0.1:17860";
const LIVE_PATH: &str = "/api/v1/health/live";
const READY_PATH: &str = "/api/v1/health/ready";
const COMMAND_OUTPUT_LIMIT: usize = 64 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const COMPOSE_TIMEOUT: Duration = Duration::from_secs(180);
const SYSTEM_BACKUP_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);
const LIVE_TIMEOUT: Duration = Duration::from_secs(90);
const READY_TIMEOUT: Duration = Duration::from_secs(180);
const SUPPORTED_MIGRATION_REVISION: &str = "20260802_0021";
const IMAGE_ENV_FILE_NAME: &str = "images.release.env";
const DOCKER_CLI_CONFIG_DIRECTORY_NAME: &str = "docker-cli-config";
const DOCKER_CLI_CONFIG_FILE_NAME: &str = "config.json";
// Docker/Compose must never consult a user's registry auths or credential helpers.  This is the
// complete, intentionally anonymous configuration accepted in the Launcher-owned directory.
const EMPTY_DOCKER_CLI_CONFIG: &[u8] = br#"{"auths":{}}"#;
const LOCAL_DOCKER_DESKTOP_ENDPOINTS: [&str; 2] = [
    "npipe:////./pipe/docker_engine",
    "npipe:////./pipe/dockerdesktoplinuxengine",
];
// Docker and Compose behaviour is selected only by Launcher-owned arguments and
// environment. Do not let an ambient platform, proxy, registry, build, or
// lifecycle override alter a command that can touch local volumes or runtime
// secrets. Docker Desktop's daemon-level organization proxy is a separate,
// user/organization-managed prerequisite and is not inherited through this CLI.
const CHILD_ENVIRONMENT_REMOVALS: &[&str] = &[
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "DOCKER_API_VERSION",
    "DOCKER_CONFIG",
    "DOCKER_AUTH_CONFIG",
    "DOCKER_DEFAULT_PLATFORM",
    "DOCKER_CUSTOM_HEADERS",
    "DOCKER_CONTENT_TRUST",
    "DOCKER_CLI_EXPERIMENTAL",
    "DOCKER_CLI_HINTS",
    "DOCKER_HIDE_LEGACY_COMMANDS",
    "DOCKER_SCAN_SUGGEST",
    "DOCKER_BUILDKIT",
    "REGISTRY_AUTH_FILE",
    "BUILDKIT_HOST",
    "BUILDKIT_PROGRESS",
    "BUILDKIT_COLORS",
    "COMPOSE_FILE",
    "COMPOSE_PROJECT_NAME",
    "COMPOSE_PROFILES",
    "COMPOSE_ENV_FILES",
    "COMPOSE_DISABLE_ENV_FILE",
    "COMPOSE_CONVERT_WINDOWS_PATHS",
    "COMPOSE_PATH_SEPARATOR",
    "COMPOSE_IGNORE_ORPHANS",
    "COMPOSE_REMOVE_ORPHANS",
    "COMPOSE_PARALLEL_LIMIT",
    "COMPOSE_ANSI",
    "COMPOSE_STATUS_STDOUT",
    "COMPOSE_MENU",
    "COMPOSE_EXPERIMENTAL",
    "COMPOSE_PROGRESS",
    "COMPOSE_BAKE",
    "COMPOSE_COMPATIBILITY",
    "COMPOSE_DOCKER_CLI_BUILD",
    "COMPOSE_INTERACTIVE_NO_CLI",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "no_proxy",
    "DES_POSTGRES_IMAGE",
    "DES_API_IMAGE",
    "DES_EGRESS_GUARD_IMAGE",
    "DES_WORKER_IMAGE",
    "DES_WEB_IMAGE",
    "DES_SECRET_DIR",
    "DES_INSTALLATION_ID",
    "DES_POSTGRES_VOLUME_NAME",
    "DES_LOG_VOLUME_NAME",
    "DES_WORKSPACE_VOLUME_NAME",
];
const EXPECTED_SERVICES: [&str; 6] = [
    "api",
    "egress-guard",
    "migrate",
    "postgres",
    "web",
    "worker",
];
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
// The tab-delimited outer framing is safe because each dynamic value is JSON encoded; tabs in
// labels or mount paths are escaped by JSON rather than emitted as framing bytes.
const COMPOSE_CONTAINER_INVENTORY_FORMAT: &str = "{{json .Id}}\t{{json .Config.Image}}\t{{json .Config.Labels}}\t{{json .Mounts}}\t{{json .State.Running}}";
const VOLUME_IDENTITY_LABEL: &str = "com.xiaoli.datax.installation-id";
const VOLUME_ROLE_LABEL: &str = "com.xiaoli.datax.volume-role";
const HELPER_CONTAINER_ROLE_LABEL: &str = "com.xiaoli.datax.helper-role";
const HELPER_CONTAINER_ID_LABEL: &str = "com.xiaoli.datax.helper-id";
const BACKUP_DATA_HELPER_ROLE: &str = "backup-data";
const BACKUP_SECRETS_HELPER_ROLE: &str = "backup-secrets";
// Phase-A QH/PAG records are deliberately outside the standard DATA backup
// trust domain. Excluding the complete private schema keeps its tables,
// trigger functions, and schema metadata out of the dump. A future protected
// issuer must invalidate all pre-restore authority and reissue fresh QH/PAG;
// this fixed value must never become a caller-configurable pg_dump pattern.
const BACKUP_EXCLUDED_PHASE_A_QUALIFICATION_SCHEMA: &str = "des_phase_a_qualification";
const RESTORE_STAGE_HELPER_ROLE: &str = "restore-stage";
const DOCKER_STORAGE_PROBE_HELPER_ROLE: &str = "storage-probe";
const HELPER_CONTAINER_INSPECT_FORMAT: &str = r#"{{ index .Config.Labels "com.xiaoli.datax.helper-role" }}|{{ index .Config.Labels "com.xiaoli.datax.helper-id" }}"#;
const RUNTIME_VOLUME_INSPECT_FORMAT: &str =
    "{{json .Name}}\t{{json .Driver}}\t{{json .Options}}\t{{json .Labels}}";
const RUNTIME_VOLUMES: [(&str, &str); 3] = [
    ("des-postgres-data", "postgres-data"),
    ("des-log-data", "log-data"),
    ("des-workspace-data", "workspace-data"),
];
// Image acquisition is explicitly complete before the Docker-volume capacity admission. Every
// subsequent Compose start must refuse an implicit pull, otherwise a concurrent prune could
// consume the measured volume after the gate and before PostgreSQL starts.
const COMPOSE_UP_WITHOUT_PULL: [&str; 4] = ["up", "--pull", "never", "-d"];
const RUNTIME_SECRET_COUNT: usize = 10;
const MAX_RUNTIME_SECRET_BYTES: u64 = 4096;
const VERIFY_CONTAINER_SECRETS_SCRIPT: &str = concat!(
    "import os,stat,sys\n",
    "spec={'/run/secrets/database_password':(64,64),",
    "'/run/secrets/jwt_private_key.pem':(1,4096),",
    "'/run/secrets/jwt_public_key.pem':(1,4096),",
    "'/run/secrets/refresh_token_hmac_key':(32,32),",
    "'/run/secrets/idempotency_hmac_key':(32,32),",
    "'/run/secrets/credential-kek-v1.key':(32,32),",
    "'/run/secrets/egress_lease_creation_capability':(64,64)}\n",
    "try:\n",
    " ok=all(stat.S_ISREG(os.lstat(p).st_mode) and lo<=os.lstat(p).st_size<=hi ",
    "for p,(lo,hi) in spec.items())\n",
    "except OSError:\n ok=False\n",
    "raise SystemExit(0 if ok else 4)\n",
);
const VERIFY_WORKER_SECRETS_SCRIPT: &str = concat!(
    "import os,stat\n",
    "spec={'/run/secrets/database_password':(64,64),",
    "'/run/secrets/idempotency_hmac_key':(32,32),",
    "'/run/secrets/credential-kek-v1.key':(32,32),",
    "'/run/secrets/egress_lease_creation_capability':(64,64)}\n",
    "try:\n",
    " ok=all(stat.S_ISREG(os.lstat(p).st_mode) and lo<=os.lstat(p).st_size<=hi ",
    "for p,(lo,hi) in spec.items())\n",
    "except OSError:\n ok=False\n",
    "raise SystemExit(0 if ok else 4)\n",
);
const VERIFY_EGRESS_GUARD_SECRET_SCRIPT: &str = concat!(
    "import os,stat\n",
    "spec={'/run/secrets/egress_guard_database_password':(64,64),",
    "'/run/secrets/egress_lease_creation_capability':(64,64)}\n",
    "try:\n",
    " ok=all(stat.S_ISREG(os.lstat(p).st_mode) and os.lstat(p).st_size==64 ",
    "for p in spec)\n",
    "except OSError:\n ok=False\n",
    "raise SystemExit(0 if ok else 4)\n",
);
const NETWORK_NAMESPACE_SCRIPT: &str = "import os; print(os.readlink('/proc/self/ns/net'), end='')";
const IMAGE_RULES: [(&str, &str); 5] = [
    ("DES_POSTGRES_IMAGE", "postgres"),
    ("DES_API_IMAGE", "ghcr.io/xiaoli2hust/datax-studio-api"),
    (
        "DES_EGRESS_GUARD_IMAGE",
        "ghcr.io/xiaoli2hust/datax-studio-egress-guard",
    ),
    (
        "DES_WORKER_IMAGE",
        "ghcr.io/xiaoli2hust/datax-studio-worker",
    ),
    ("DES_WEB_IMAGE", "ghcr.io/xiaoli2hust/datax-studio-web"),
];
const RELEASE_MANIFEST_BOUND_SHA256: Option<&str> = option_env!("DES_RELEASE_MANIFEST_SHA256");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherError {
    code: String,
    message: String,
}

impl LauncherError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LauncherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LauncherError {}

pub fn process_exit_code(error: &LauncherError) -> u8 {
    match error.code() {
        "ACTIVE_ATTEMPTS_PRESENT" => 3,
        "FORCE_STOP_CANCELED" => 2,
        _ => 1,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Start,
    Stop {
        force: bool,
    },
    Backup {
        data_output: PathBuf,
        secrets_output: PathBuf,
        data_key: PathBuf,
        secrets_key: PathBuf,
    },
    Restore {
        data_input: PathBuf,
        secrets_input: PathBuf,
        data_key: PathBuf,
        secrets_key: PathBuf,
    },
    VerifyRelease {
        installer: PathBuf,
    },
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Started,
    BootstrapCanceled,
    Stopped,
    BackupCreated {
        data_package: PathBuf,
        secrets_package: PathBuf,
    },
    ReleaseVerified,
    Help(String),
}

pub(crate) struct BootstrapInput {
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) password_utf16: Zeroizing<Vec<u16>>,
}

#[derive(Debug)]
struct Installation {
    executable: PathBuf,
    install_dir: PathBuf,
    compose_file: PathBuf,
    image_env_file: PathBuf,
    acl_script: PathBuf,
    release_manifest: PathBuf,
    local_app_data: PathBuf,
    app_data_root: PathBuf,
    docker_cli_config_dir: PathBuf,
    docker_cli_config_file: PathBuf,
    initialization_state: PathBuf,
    installation_id: PathBuf,
    runtime_generation: PathBuf,
    secret_dir: PathBuf,
    postgres_secret: PathBuf,
    egress_guard_database_secret: PathBuf,
    egress_lease_creation_capability: PathBuf,
    api_database_secret: PathBuf,
    worker_database_secret: PathBuf,
    jwt_private_key: PathBuf,
    jwt_public_key: PathBuf,
    refresh_token_hmac_key: PathBuf,
    idempotency_hmac_key: PathBuf,
    credential_kek: PathBuf,
}

#[derive(Debug)]
struct Tools {
    docker: PathBuf,
    compose: PathBuf,
    docker_host: Option<OsString>,
    docker_cli_config_dir: PathBuf,
    reg: PathBuf,
}

#[derive(Debug)]
struct StartTools {
    wsl: PathBuf,
    whoami: PathBuf,
    powershell: PathBuf,
    netstat: PathBuf,
}

#[derive(Debug)]
struct ProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HelperContainer {
    name: String,
    role: &'static str,
    opaque_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureFailure {
    Read,
    Truncated,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    schema_version: String,
    product_version: String,
    compose_sha256: String,
    images_sha256: String,
    acl_script_sha256: String,
    allowed_authenticode_signer_certificate_sha256: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedRelease {
    image_lock: ImageLock,
    allowed_authenticode_signers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageLock {
    postgres: String,
    api: String,
    egress_guard: String,
    worker: String,
    web: String,
}

impl ImageLock {
    fn for_service(&self, service: &str) -> Option<&str> {
        match service {
            "postgres" => Some(&self.postgres),
            "api" | "migrate" => Some(&self.api),
            "egress-guard" => Some(&self.egress_guard),
            "worker" => Some(&self.worker),
            "web" => Some(&self.web),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct ComposeContainerMount {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Name", default)]
    name: Option<String>,
    #[serde(rename = "Destination")]
    destination: String,
    #[serde(rename = "RW")]
    read_write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InspectedComposeContainer {
    id: String,
    image: String,
    labels: BTreeMap<String, String>,
    mounts: Vec<ComposeContainerMount>,
    running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedComposeContainer {
    id: String,
    running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComposeProjectInventory {
    Empty,
    Verified(BTreeMap<String, AuthenticatedComposeContainer>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeVolumeNames {
    postgres: String,
    logs: String,
    workspace: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeSecretPaths {
    directory: PathBuf,
    postgres: PathBuf,
    egress_guard_database: PathBuf,
    egress_lease_creation_capability: PathBuf,
    api_database: PathBuf,
    worker_database: PathBuf,
    jwt_private_key: PathBuf,
    jwt_public_key: PathBuf,
    refresh_token_hmac_key: PathBuf,
    idempotency_hmac_key: PathBuf,
    credential_kek: PathBuf,
}

impl RuntimeSecretPaths {
    fn from_directory(directory: PathBuf) -> Self {
        Self {
            postgres: directory.join("postgres_password.txt"),
            egress_guard_database: directory.join("egress_guard_database_password.txt"),
            egress_lease_creation_capability: directory.join("egress_lease_creation_capability"),
            api_database: directory.join("api_database_password.txt"),
            worker_database: directory.join("worker_database_password.txt"),
            jwt_private_key: directory.join("jwt_private_key.pem"),
            jwt_public_key: directory.join("jwt_public_key.pem"),
            refresh_token_hmac_key: directory.join("refresh_token_hmac_key"),
            idempotency_hmac_key: directory.join("idempotency_hmac_key"),
            credential_kek: directory.join("credential-kek-v1.key"),
            directory,
        }
    }

    fn all(&self) -> [&Path; RUNTIME_SECRET_COUNT] {
        [
            self.postgres.as_path(),
            self.egress_guard_database.as_path(),
            self.egress_lease_creation_capability.as_path(),
            self.api_database.as_path(),
            self.worker_database.as_path(),
            self.jwt_private_key.as_path(),
            self.jwt_public_key.as_path(),
            self.refresh_token_hmac_key.as_path(),
            self.idempotency_hmac_key.as_path(),
            self.credential_kek.as_path(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveRuntimeSnapshot {
    generation: RuntimeGeneration,
    secrets: RuntimeSecretPaths,
    volumes: RuntimeVolumeNames,
}

impl ActiveRuntimeSnapshot {
    fn from_generation(
        app_data_root: &Path,
        generation: RuntimeGeneration,
    ) -> Result<Self, LauncherError> {
        generation.validate()?;
        let secret_directory = generation.secret_path(app_data_root);
        if !secret_directory.starts_with(app_data_root) {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_INVALID",
                "活动运行代际的 secret 目录超出固定应用数据根。",
            ));
        }
        let volumes = RuntimeVolumeNames {
            postgres: generation.volumes.postgres.clone(),
            logs: generation.volumes.logs.clone(),
            workspace: generation.volumes.workspace.clone(),
        };
        let distinct = [
            volumes.postgres.as_str(),
            volumes.logs.as_str(),
            volumes.workspace.as_str(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if distinct.len() != 3 {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_INVALID",
                "活动运行代际引用了重复的运行数据卷名称。",
            ));
        }
        Ok(Self {
            generation,
            secrets: RuntimeSecretPaths::from_directory(secret_directory),
            volumes,
        })
    }

    fn compose_environment(&self, app_data_root: &Path) -> Vec<(OsString, OsString)> {
        self.generation.compose_environment(app_data_root)
    }

    fn volume_contract(&self) -> ActiveRuntimeVolumeContract {
        ActiveRuntimeVolumeContract {
            installation_id: self.generation.installation_id.clone(),
            names: self.volumes.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveRuntimeVolumeContract {
    installation_id: String,
    names: RuntimeVolumeNames,
}

impl ComposeProjectInventory {
    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    fn has_service(&self, service: &str) -> bool {
        matches!(self, Self::Verified(services) if services.contains_key(service))
    }

    fn service_is_running(&self, service: &str) -> bool {
        matches!(self, Self::Verified(services) if services.get(service).is_some_and(|container| container.running))
    }

    fn is_complete(&self) -> bool {
        matches!(self, Self::Verified(services) if services.len() == EXPECTED_SERVICES.len()
            && EXPECTED_SERVICES.iter().all(|service| services.contains_key(*service)))
    }

    fn container_ids(&self) -> Vec<&str> {
        match self {
            Self::Empty => Vec::new(),
            Self::Verified(services) => services
                .values()
                .map(|container| container.id.as_str())
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct StopPreflight {
    safe_to_stop: bool,
    code: String,
    #[serde(default)]
    active_execution_count: u64,
    #[serde(default)]
    active_probe_count: u64,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BootstrapStatus {
    required: Option<bool>,
    code: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BootstrapCreateResult {
    created: bool,
    code: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SystemBackupResult {
    schema_version: String,
    code: String,
    kind: String,
    backup_id: String,
    filename: String,
    package_bytes: u64,
    package_sha256: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RestoreStageResult {
    schema_version: String,
    code: String,
    journal_id: String,
    state: String,
    data_backup_id: String,
    secrets_backup_id: String,
    installation_id: String,
    next_required_gate: String,
}

#[derive(Debug)]
struct PreparedRestore {
    data_input: PathBuf,
    secrets_input: PathBuf,
    data_key: Zeroizing<Vec<u8>>,
    secrets_key: Zeroizing<Vec<u8>>,
    staging_root: PathBuf,
    journal_directory: PathBuf,
    journal_path: PathBuf,
    current_user_sid: String,
}

#[derive(Debug)]
struct PreparedBackup {
    data_output: PathBuf,
    secrets_output: PathBuf,
    data_key: Zeroizing<Vec<u8>>,
    secrets_key: Zeroizing<Vec<u8>>,
    active_runtime: ActiveRuntimeSnapshot,
    installation_id: String,
    current_user_sid: String,
}

#[derive(Debug)]
struct BackupStaging {
    directory: PathBuf,
    postgres_dump: PathBuf,
}

#[derive(Debug, Clone, Copy)]
struct BackupRequestPaths<'a> {
    data_output: &'a Path,
    secrets_output: &'a Path,
    data_key: &'a Path,
    secrets_key: &'a Path,
}

#[derive(Debug, Clone, Copy)]
struct RestoreRequestPaths<'a> {
    data_input: &'a Path,
    secrets_input: &'a Path,
    data_key: &'a Path,
    secrets_key: &'a Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapState {
    Required,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapCreateState {
    Created,
    AlreadyCompleted,
    InputInvalid,
    InternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpProbe {
    Unreachable,
    Status(u16),
    InvalidResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageIdentityDecision {
    Fresh,
    Existing,
    IncompleteVolumes,
    IdentityLost,
    MarkerMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitializationRecoveryDecision {
    RegenerateSecrets,
    CompleteVolumes,
    Finalize,
    Unsafe,
}

pub fn run<I>(arguments: I) -> Result<RunOutcome, LauncherError>
where
    I: IntoIterator<Item = OsString>,
{
    let action = parse_action(arguments)?;
    if action == Action::Help {
        return Ok(RunOutcome::Help(help_text()));
    }

    platform::ensure_supported_host()?;
    let _instance = platform::acquire_single_instance()?;
    let installation = Installation::discover()?;
    platform::ensure_authenticode_trusted(&installation.executable)?;
    let verified_release = verify_release_resources(&installation)?;
    let launcher_signer = platform::ensure_authenticode_signer_sha256(
        &installation.executable,
        &verified_release.allowed_authenticode_signers,
    )?;

    match action {
        Action::Start => {
            ensure_no_restore_in_progress(&installation.app_data_root)?;
            platform::ensure_hardware_prerequisites(&installation.local_app_data)?;
            let start_tools = StartTools::discover()?;
            let mut tools = Tools::discover(&installation, &start_tools)?;
            verify_prerequisites(&mut tools, &start_tools, &installation)?;
            ensure_release_images_available(&tools, &installation, &verified_release.image_lock)?;
            ensure_runtime_secrets(&tools, &start_tools, &installation)?;
            ensure_docker_storage_capacity(&tools, &installation, &verified_release.image_lock)?;
            verify_compose_config(&tools, &installation, &verified_release.image_lock)?;
            if start(
                &tools,
                &start_tools,
                &installation,
                &verified_release.image_lock,
            )? {
                Ok(RunOutcome::Started)
            } else {
                Ok(RunOutcome::BootstrapCanceled)
            }
        }
        Action::Stop { force } => {
            let start_tools = StartTools::discover()?;
            let mut tools = Tools::discover(&installation, &start_tools)?;
            configure_local_docker_endpoint(&mut tools, &installation)?;
            stop(&tools, &installation, &verified_release.image_lock, force)?;
            Ok(RunOutcome::Stopped)
        }
        Action::Backup {
            data_output,
            secrets_output,
            data_key,
            secrets_key,
        } => {
            ensure_no_restore_in_progress(&installation.app_data_root)?;
            platform::ensure_hardware_prerequisites(&installation.local_app_data)?;
            let start_tools = StartTools::discover()?;
            let mut tools = Tools::discover(&installation, &start_tools)?;
            verify_prerequisites(&mut tools, &start_tools, &installation)?;
            ensure_release_images_available(&tools, &installation, &verified_release.image_lock)?;
            ensure_docker_storage_capacity(&tools, &installation, &verified_release.image_lock)?;
            let (data_package, secrets_package) = create_system_backup(
                &tools,
                &start_tools,
                &installation,
                &verified_release.image_lock,
                BackupRequestPaths {
                    data_output: &data_output,
                    secrets_output: &secrets_output,
                    data_key: &data_key,
                    secrets_key: &secrets_key,
                },
            )?;
            Ok(RunOutcome::BackupCreated {
                data_package,
                secrets_package,
            })
        }
        Action::Restore {
            data_input,
            secrets_input,
            data_key,
            secrets_key,
        } => {
            platform::ensure_hardware_prerequisites(&installation.local_app_data)?;
            let start_tools = StartTools::discover()?;
            let mut tools = Tools::discover(&installation, &start_tools)?;
            verify_prerequisites(&mut tools, &start_tools, &installation)?;
            ensure_release_images_available(&tools, &installation, &verified_release.image_lock)?;
            stage_system_restore(
                &tools,
                &start_tools,
                &installation,
                &verified_release.image_lock,
                RestoreRequestPaths {
                    data_input: &data_input,
                    secrets_input: &secrets_input,
                    data_key: &data_key,
                    secrets_key: &secrets_key,
                },
            )
        }
        Action::VerifyRelease { installer } => {
            platform::ensure_local_disk_path(&installer)?;
            platform::ensure_regular_file(&installer)?;
            let installer_signer = platform::ensure_authenticode_signer_sha256(
                &installer,
                &verified_release.allowed_authenticode_signers,
            )?;
            if !constant_time_ascii_equal(&launcher_signer, &installer_signer) {
                return Err(LauncherError::new(
                    "AUTHENTICODE_SIGNER_MISMATCH",
                    "Setup 与 Launcher 不是由同一固定发布证书签名，已拒绝安装。",
                ));
            }
            Ok(RunOutcome::ReleaseVerified)
        }
        Action::Help => unreachable!("help returns before platform checks"),
    }
}

fn parse_action<I>(arguments: I) -> Result<Action, LauncherError>
where
    I: IntoIterator<Item = OsString>,
{
    let values: Vec<OsString> = arguments.into_iter().collect();
    match values.as_slice() {
        [] => Ok(Action::Start),
        [value] if value == "start" => Ok(Action::Start),
        [value] if value == "stop" => Ok(Action::Stop { force: false }),
        [value] if value == "help" || value == "--help" || value == "-h" => Ok(Action::Help),
        [first, second] if first == "stop" && (second == "--force" || second == "-f") => {
            Ok(Action::Stop { force: true })
        }
        [
            command,
            data_option,
            data_output,
            secrets_option,
            secrets_output,
            data_key_option,
            data_key,
            secrets_key_option,
            secrets_key,
        ] if command == "backup"
            && data_option == "--data-output"
            && !data_output.is_empty()
            && secrets_option == "--secrets-output"
            && !secrets_output.is_empty()
            && data_key_option == "--data-key"
            && !data_key.is_empty()
            && secrets_key_option == "--secrets-key"
            && !secrets_key.is_empty() =>
        {
            Ok(Action::Backup {
                data_output: PathBuf::from(data_output),
                secrets_output: PathBuf::from(secrets_output),
                data_key: PathBuf::from(data_key),
                secrets_key: PathBuf::from(secrets_key),
            })
        }
        [
            command,
            data_option,
            data_input,
            secrets_option,
            secrets_input,
            data_key_option,
            data_key,
            secrets_key_option,
            secrets_key,
        ] if command == "restore"
            && data_option == "--data-input"
            && !data_input.is_empty()
            && secrets_option == "--secrets-input"
            && !secrets_input.is_empty()
            && data_key_option == "--data-key"
            && !data_key.is_empty()
            && secrets_key_option == "--secrets-key"
            && !secrets_key.is_empty() =>
        {
            Ok(Action::Restore {
                data_input: PathBuf::from(data_input),
                secrets_input: PathBuf::from(secrets_input),
                data_key: PathBuf::from(data_key),
                secrets_key: PathBuf::from(secrets_key),
            })
        }
        [command, option, installer]
            if command == "verify-release" && option == "--installer" && !installer.is_empty() =>
        {
            Ok(Action::VerifyRelease {
                installer: PathBuf::from(installer),
            })
        }
        _ => Err(LauncherError::new(
            "INVALID_ARGUMENTS",
            "仅支持 start、stop、受控 backup、失败关闭的 restore、help，或安装器内部核验命令；执行 help 查看固定参数。",
        )),
    }
}

fn help_text() -> String {
    [
        PRODUCT_NAME,
        "",
        "直接启动：检查 Windows/WSL2/Docker/Compose，启动本机服务，就绪后打开浏览器。",
        "stop：先执行容器内安全停止预检；存在活动 Attempt 时拒绝停止。",
        "stop --force：确认风险后强制停止；不删除 Docker named volumes。",
        "backup --data-output <本地目录> --secrets-output <另一目录> --data-key <64位小写hex文件> --secrets-key <另一64位小写hex文件>：安全停机后生成分离加密备份；四个路径不得重合，两个 key 内容必须不同。",
        "restore --data-input <.dxdata> --secrets-input <.dxkeys> --data-key <key文件> --secrets-key <key文件>：只在干净目标认证并 staging 配对包，随后返回 RESTORE_STAGED_COMMIT_BLOCKED；不创建运行卷，不等于系统恢复。",
        "verify-release --installer <Setup.exe>：安装器内部使用的发布签名一致性核验。",
    ]
    .join("\n")
}

impl Installation {
    fn discover() -> Result<Self, LauncherError> {
        let executable = env::current_exe().map_err(|_| {
            LauncherError::new("INSTALL_PATH_UNAVAILABLE", "无法解析 Launcher 安装路径。")
        })?;
        platform::ensure_local_disk_path(&executable)?;
        let install_dir = executable
            .parent()
            .ok_or_else(|| {
                LauncherError::new("INSTALL_PATH_UNAVAILABLE", "Launcher 安装路径没有父目录。")
            })?
            .to_path_buf();
        platform::ensure_tree_no_reparse(&install_dir)?;
        platform::ensure_directory(&install_dir)?;

        let resources = install_dir.join("resources");
        platform::ensure_directory(&resources)?;
        let compose_file = resources.join("compose.yaml");
        let image_env_file = resources.join(IMAGE_ENV_FILE_NAME);
        let acl_script = resources.join("secure-acl.ps1");
        let release_manifest = resources.join("release-manifest.json");
        platform::ensure_regular_file(&compose_file)?;
        platform::ensure_regular_file(&image_env_file)?;
        platform::ensure_regular_file(&acl_script)?;
        platform::ensure_regular_file(&release_manifest)?;

        let local_app_data = platform::local_app_data_directory()?;
        let app_data_root = local_app_data.join("DataXEnterpriseStudio");
        let docker_cli_config_dir = app_data_root.join(DOCKER_CLI_CONFIG_DIRECTORY_NAME);
        let docker_cli_config_file = docker_cli_config_dir.join(DOCKER_CLI_CONFIG_FILE_NAME);
        let initialization_state = app_data_root.join("initialization-incomplete");
        let installation_id = app_data_root.join("installation-id");
        let runtime_generation = app_data_root.join("runtime-generation.json");
        let secret_dir = app_data_root.join("secrets");
        let postgres_secret = secret_dir.join("postgres_password.txt");
        let egress_guard_database_secret = secret_dir.join("egress_guard_database_password.txt");
        let egress_lease_creation_capability = secret_dir.join("egress_lease_creation_capability");
        let api_database_secret = secret_dir.join("api_database_password.txt");
        let worker_database_secret = secret_dir.join("worker_database_password.txt");
        let jwt_private_key = secret_dir.join("jwt_private_key.pem");
        let jwt_public_key = secret_dir.join("jwt_public_key.pem");
        let refresh_token_hmac_key = secret_dir.join("refresh_token_hmac_key");
        let idempotency_hmac_key = secret_dir.join("idempotency_hmac_key");
        let credential_kek = secret_dir.join("credential-kek-v1.key");

        Ok(Self {
            executable,
            install_dir,
            compose_file,
            image_env_file,
            acl_script,
            release_manifest,
            local_app_data,
            app_data_root,
            docker_cli_config_dir,
            docker_cli_config_file,
            initialization_state,
            installation_id,
            runtime_generation,
            secret_dir,
            postgres_secret,
            egress_guard_database_secret,
            egress_lease_creation_capability,
            api_database_secret,
            worker_database_secret,
            jwt_private_key,
            jwt_public_key,
            refresh_token_hmac_key,
            idempotency_hmac_key,
            credential_kek,
        })
    }

    fn compose_environment(&self) -> Result<Vec<(OsString, OsString)>, LauncherError> {
        let active_runtime = load_active_runtime_snapshot(self)?;
        Ok(self.compose_environment_for(&active_runtime))
    }

    fn compose_environment_for(
        &self,
        active_runtime: &ActiveRuntimeSnapshot,
    ) -> Vec<(OsString, OsString)> {
        active_runtime.compose_environment(&self.app_data_root)
    }
}

impl Tools {
    fn discover(
        installation: &Installation,
        start_tools: &StartTools,
    ) -> Result<Self, LauncherError> {
        ensure_isolated_docker_cli_config(start_tools, installation)?;
        let reg = platform::system32_executable("reg.exe")?;
        let install_path = query_registry_string(
            &reg,
            &installation.install_dir,
            r"HKLM\SOFTWARE\Docker Inc.\Docker Desktop",
            "InstallPath",
        )?
        .or(query_registry_string(
            &reg,
            &installation.install_dir,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop",
            "InstallLocation",
        )?)
        .ok_or_else(|| {
            LauncherError::new(
                "DOCKER_DESKTOP_MISSING",
                "未在受信 HKLM 注册表位置找到 Docker Desktop。请从官方渠道安装并接受适用许可。",
            )
        })?;
        let docker_candidate = PathBuf::from(install_path)
            .join("resources")
            .join("bin")
            .join("docker.exe");
        let compose_candidate = docker_candidate
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| {
                LauncherError::new("DOCKER_CLI_UNSAFE", "Docker Desktop 安装路径结构无效。")
            })?
            .join("cli-plugins")
            .join("docker-compose.exe");
        let program_files = platform::program_files_directory()?;
        platform::ensure_trusted_descendant(&program_files, &docker_candidate)?;
        platform::ensure_trusted_descendant(&program_files, &compose_candidate)?;
        let docker = fs::canonicalize(&docker_candidate).map_err(|_| {
            LauncherError::new("DOCKER_CLI_UNSAFE", "Docker CLI 路径无法安全解析。")
        })?;
        let compose = fs::canonicalize(&compose_candidate).map_err(|_| {
            LauncherError::new(
                "DOCKER_COMPOSE_UNSAFE",
                "Docker Compose 固定插件路径无法安全解析。",
            )
        })?;
        platform::ensure_authenticode_publisher(
            &docker,
            &["Docker Inc", "Docker Inc.", "Docker, Inc."],
        )?;
        platform::ensure_authenticode_publisher(
            &compose,
            &["Docker Inc", "Docker Inc.", "Docker, Inc."],
        )?;

        Ok(Self {
            docker,
            compose,
            docker_host: None,
            docker_cli_config_dir: installation.docker_cli_config_dir.clone(),
            reg,
        })
    }

    fn docker_environment(&self) -> Vec<(OsString, OsString)> {
        let mut environment = vec![(
            OsString::from("DOCKER_CONFIG"),
            self.docker_cli_config_dir.as_os_str().to_os_string(),
        )];
        if let Some(host) = &self.docker_host {
            environment.push((OsString::from("DOCKER_HOST"), host.clone()));
        }
        environment
    }
}

impl StartTools {
    fn discover() -> Result<Self, LauncherError> {
        let powershell = platform::windows_powershell_executable()?;
        platform::ensure_authenticode_trusted(&powershell)?;
        Ok(Self {
            wsl: platform::system32_executable("wsl.exe")?,
            whoami: platform::system32_executable("whoami.exe")?,
            powershell,
            netstat: platform::system32_executable("netstat.exe")?,
        })
    }
}

fn ensure_isolated_docker_cli_config(
    start_tools: &StartTools,
    installation: &Installation,
) -> Result<(), LauncherError> {
    let local_app_data = installation.app_data_root.parent().ok_or_else(|| {
        LauncherError::new(
            "LOCALAPPDATA_UNAVAILABLE",
            "Windows LOCALAPPDATA 目录结构无效。",
        )
    })?;
    platform::ensure_directory(local_app_data)?;
    create_controlled_directory(&installation.app_data_root)?;
    platform::ensure_tree_no_reparse(&installation.app_data_root)?;

    let sid = current_user_sid(start_tools, installation)?;
    restrict_directory_acl(start_tools, installation, &installation.app_data_root, &sid)?;
    create_controlled_directory(&installation.docker_cli_config_dir)?;
    platform::ensure_tree_no_reparse(&installation.docker_cli_config_dir)?;
    restrict_directory_acl(
        start_tools,
        installation,
        &installation.docker_cli_config_dir,
        &sid,
    )?;

    match fs::symlink_metadata(&installation.docker_cli_config_file) {
        Ok(_) => {
            platform::ensure_regular_file(&installation.docker_cli_config_file)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut config = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&installation.docker_cli_config_file)
                .map_err(|_| {
                    LauncherError::new(
                        "DOCKER_CONFIG_CREATE_FAILED",
                        "无法创建 Launcher 受控的空 Docker CLI 配置。",
                    )
                })?;
            config.write_all(EMPTY_DOCKER_CLI_CONFIG).map_err(|_| {
                LauncherError::new(
                    "DOCKER_CONFIG_CREATE_FAILED",
                    "无法写入 Launcher 受控的空 Docker CLI 配置。",
                )
            })?;
            config.sync_all().map_err(|_| {
                LauncherError::new(
                    "DOCKER_CONFIG_CREATE_FAILED",
                    "无法持久化 Launcher 受控的空 Docker CLI 配置。",
                )
            })?;
            platform::ensure_regular_file(&installation.docker_cli_config_file)?;
        }
        Err(_) => {
            return Err(LauncherError::new(
                "DOCKER_CONFIG_INVALID",
                "无法检查 Launcher 受控的 Docker CLI 配置。",
            ));
        }
    }
    restrict_file_acl(
        start_tools,
        installation,
        &installation.docker_cli_config_file,
        &sid,
    )?;
    validate_isolated_docker_cli_config(
        &installation.docker_cli_config_dir,
        &installation.docker_cli_config_file,
    )
}

fn validate_isolated_docker_cli_config(
    directory: &Path,
    config_file: &Path,
) -> Result<(), LauncherError> {
    platform::ensure_directory(directory)?;
    platform::ensure_regular_file(config_file)?;
    let entries = fs::read_dir(directory).map_err(|_| {
        LauncherError::new(
            "DOCKER_CONFIG_INVALID",
            "无法枚举 Launcher 受控的 Docker CLI 配置目录。",
        )
    })?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| {
            LauncherError::new(
                "DOCKER_CONFIG_INVALID",
                "无法读取 Launcher 受控的 Docker CLI 配置目录。",
            )
        })?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            LauncherError::new(
                "DOCKER_CONFIG_INVALID",
                "Docker CLI 配置目录包含无效文件名。",
            )
        })?;
        names.insert(name.to_owned());
    }
    if names.len() != 1 || !names.contains(DOCKER_CLI_CONFIG_FILE_NAME) {
        return Err(LauncherError::new(
            "DOCKER_CONFIG_INVALID",
            "Docker CLI 配置目录必须只包含 Launcher 生成的空 config.json。",
        ));
    }
    let contents = read_bounded_file(config_file, 1024, "DOCKER_CONFIG_INVALID")?;
    if contents.as_slice() != EMPTY_DOCKER_CLI_CONFIG {
        return Err(LauncherError::new(
            "DOCKER_CONFIG_INVALID",
            "Docker CLI 配置不是受控的匿名配置；已拒绝读取 registry 凭据或 credential helper。",
        ));
    }
    Ok(())
}

fn verify_release_resources(installation: &Installation) -> Result<VerifiedRelease, LauncherError> {
    let manifest_metadata = fs::metadata(&installation.release_manifest).map_err(|_| {
        LauncherError::new("RELEASE_MANIFEST_UNAVAILABLE", "无法读取发布资源清单。")
    })?;
    if manifest_metadata.len() > 64 * 1024 {
        return Err(LauncherError::new(
            "RELEASE_MANIFEST_INVALID",
            "发布资源清单超过允许大小。",
        ));
    }
    let manifest_bytes = fs::read(&installation.release_manifest).map_err(|_| {
        LauncherError::new("RELEASE_MANIFEST_UNAVAILABLE", "无法读取发布资源清单。")
    })?;
    let expected_manifest_hash = RELEASE_MANIFEST_BOUND_SHA256.ok_or_else(|| {
        LauncherError::new(
            "RELEASE_BINDING_MISSING",
            "Launcher 构建未绑定发布资源清单；该构建不得用于 Windows 发布。",
        )
    })?;
    if !is_sha256(expected_manifest_hash)
        || !constant_time_ascii_equal(
            &hex_lower(&Sha256::digest(&manifest_bytes)),
            expected_manifest_hash,
        )
    {
        return Err(LauncherError::new(
            "RELEASE_MANIFEST_INTEGRITY_FAILED",
            "发布资源清单与已签名 Launcher 内置摘要不一致。",
        ));
    }
    let manifest = parse_release_manifest(&manifest_bytes)?;

    let compose_metadata = fs::metadata(&installation.compose_file).map_err(|_| {
        LauncherError::new("COMPOSE_FILE_UNAVAILABLE", "无法读取固定 Compose 清单。")
    })?;
    if compose_metadata.len() > 1024 * 1024 {
        return Err(LauncherError::new(
            "COMPOSE_FILE_INVALID",
            "Compose 清单超过允许大小。",
        ));
    }
    let compose_bytes = fs::read(&installation.compose_file).map_err(|_| {
        LauncherError::new("COMPOSE_FILE_UNAVAILABLE", "无法读取固定 Compose 清单。")
    })?;
    let actual = hex_lower(&Sha256::digest(compose_bytes));
    if !constant_time_ascii_equal(&actual, &manifest.compose_sha256) {
        return Err(LauncherError::new(
            "COMPOSE_INTEGRITY_FAILED",
            "固定 Compose 清单与发布资源清单不一致，已拒绝启动。",
        ));
    }
    let image_bytes = read_bounded_file(
        &installation.image_env_file,
        16 * 1024,
        "IMAGE_LOCK_UNAVAILABLE",
    )?;
    let image_actual = hex_lower(&Sha256::digest(&image_bytes));
    if !constant_time_ascii_equal(&image_actual, &manifest.images_sha256) {
        return Err(LauncherError::new(
            "IMAGE_LOCK_INTEGRITY_FAILED",
            "发布镜像锁与发布资源清单不一致，已拒绝启动。",
        ));
    }
    let acl_bytes = read_bounded_file(
        &installation.acl_script,
        128 * 1024,
        "ACL_SCRIPT_UNAVAILABLE",
    )?;
    let acl_actual = hex_lower(&Sha256::digest(acl_bytes));
    if !constant_time_ascii_equal(&acl_actual, &manifest.acl_script_sha256) {
        return Err(LauncherError::new(
            "ACL_SCRIPT_INTEGRITY_FAILED",
            "受控 ACL helper 与发布资源清单不一致，已拒绝启动。",
        ));
    }
    Ok(VerifiedRelease {
        image_lock: parse_image_lock(&image_bytes)?,
        allowed_authenticode_signers: manifest.allowed_authenticode_signer_certificate_sha256,
    })
}

fn parse_release_manifest(bytes: &[u8]) -> Result<ReleaseManifest, LauncherError> {
    let manifest: ReleaseManifest = serde_json::from_slice(bytes).map_err(|_| {
        LauncherError::new(
            "RELEASE_MANIFEST_INVALID",
            "发布资源清单不是受支持的 JSON。",
        )
    })?;
    let signers = &manifest.allowed_authenticode_signer_certificate_sha256;
    let signer_set_is_canonical = (1..=8).contains(&signers.len())
        && signers.iter().all(|value| is_sha256(value))
        && signers.windows(2).all(|values| values[0] < values[1]);
    if manifest.schema_version != "1.1"
        || manifest.product_version != env!("CARGO_PKG_VERSION")
        || !is_sha256(&manifest.compose_sha256)
        || !is_sha256(&manifest.images_sha256)
        || !is_sha256(&manifest.acl_script_sha256)
        || !signer_set_is_canonical
    {
        return Err(LauncherError::new(
            "RELEASE_MANIFEST_INVALID",
            "发布资源清单版本、哈希字段或发布证书允许集无效。",
        ));
    }
    Ok(manifest)
}

fn verify_prerequisites(
    tools: &mut Tools,
    start_tools: &StartTools,
    installation: &Installation,
) -> Result<(), LauncherError> {
    let current_version_key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let installation_type = query_registry_string(
        &tools.reg,
        &installation.install_dir,
        current_version_key,
        "InstallationType",
    )?
    .ok_or_else(|| {
        LauncherError::new(
            "WINDOWS_EDITION_UNVERIFIED",
            "无法核验 Windows InstallationType。",
        )
    })?;
    let product_name = query_registry_string(
        &tools.reg,
        &installation.install_dir,
        current_version_key,
        "ProductName",
    )?
    .ok_or_else(|| {
        LauncherError::new(
            "WINDOWS_EDITION_UNVERIFIED",
            "无法核验 Windows ProductName。",
        )
    })?;
    if !installation_type.eq_ignore_ascii_case("Client")
        || product_name.to_ascii_lowercase().contains("server")
    {
        return Err(LauncherError::new(
            "WINDOWS_SERVER_REJECTED",
            "Windows Server/非客户端 edition 不属于 V1 支持范围。",
        ));
    }

    let wsl = run_process(
        &start_tools.wsl,
        &[OsString::from("--status")],
        &[],
        &installation.install_dir,
        PROCESS_TIMEOUT,
    )?;
    require_wsl_status(wsl.status.success())?;

    configure_local_docker_endpoint(tools, installation)?;

    let version = docker(
        tools,
        installation,
        &["version", "--format", "{{.Server.Os}}|{{.Server.Arch}}"],
        PROCESS_TIMEOUT,
    )?;
    if !docker_reports_linux_amd64(version.status.success(), &version.stdout) {
        return Err(LauncherError::new(
            "DOCKER_LINUX_ENGINE_REQUIRED",
            "Docker Desktop Linux Engine 未运行或不是 amd64。Launcher 不会切换容器模式。",
        ));
    }

    let info = docker(
        tools,
        installation,
        &[
            "info",
            "--format",
            "{{.OperatingSystem}}|{{.OSType}}|{{.Architecture}}",
        ],
        PROCESS_TIMEOUT,
    )?;
    if !docker_reports_desktop_linux(info.status.success(), &info.stdout) {
        return Err(LauncherError::new(
            "DOCKER_DESKTOP_REQUIRED",
            "需要正在运行的本机 Docker Desktop Linux Engine。",
        ));
    }

    let compose_version = run_process(
        &tools.compose,
        &[OsString::from("version"), OsString::from("--short")],
        &tools.docker_environment(),
        &installation.install_dir,
        PROCESS_TIMEOUT,
    )?;
    if !compose_version.status.success()
        || normalize_text(&compose_version.stdout).trim().is_empty()
    {
        return Err(LauncherError::new(
            "DOCKER_COMPOSE_REQUIRED",
            "Docker Compose v2 不可用。",
        ));
    }

    Ok(())
}

// `HKCU\\...\\Lxss\\DefaultVersion` only affects the version assigned to a newly
// installed distribution. It is deliberately not an admission input: this preflight needs
// WSL availability plus the independently verified, local Docker Desktop Linux engine below.
fn require_wsl_status(status_succeeded: bool) -> Result<(), LauncherError> {
    if status_succeeded {
        return Ok(());
    }
    Err(LauncherError::new(
        "WSL2_REQUIRED",
        "WSL2 不可用。请按 Microsoft 官方说明启用 WSL2；Launcher 不会自动安装。",
    ))
}

fn docker_reports_linux_amd64(status_succeeded: bool, stdout: &[u8]) -> bool {
    status_succeeded
        && normalize_text(stdout)
            .trim()
            .eq_ignore_ascii_case("linux|amd64")
}

fn docker_reports_desktop_linux(status_succeeded: bool, stdout: &[u8]) -> bool {
    let info_text = normalize_text(stdout).to_ascii_lowercase();
    status_succeeded && info_text.contains("docker desktop") && info_text.contains("|linux|")
}

// A later product `docker run` or `compose up` must never pull after the volume capacity probe.
// Make all disk-affecting, immutable-digest acquisition explicit and complete first. Cached images
// are accepted without contacting a registry, so an already-installed workstation can still start
// offline; a missing image is fetched only through the Launcher-owned anonymous Docker config.
fn ensure_release_images_available(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<(), LauncherError> {
    for image in release_image_references(image_lock) {
        let inspected = docker(
            tools,
            installation,
            &[
                "image",
                "inspect",
                "--format",
                "{{.Os}}|{{.Architecture}}",
                image,
            ],
            PROCESS_TIMEOUT,
        )?;
        if docker_reports_linux_amd64(inspected.status.success(), &inspected.stdout) {
            continue;
        }

        let pulled = docker(
            tools,
            installation,
            &[
                "image",
                "pull",
                "--platform",
                "linux/amd64",
                "--quiet",
                image,
            ],
            COMPOSE_TIMEOUT,
        )?;
        if !pulled.status.success() {
            return Err(LauncherError::new(
                "RELEASE_IMAGE_PULL_FAILED",
                "无法以固定 digest 获取所需发布镜像；未继续初始化或启动产品服务。",
            ));
        }
        let rechecked = docker(
            tools,
            installation,
            &[
                "image",
                "inspect",
                "--format",
                "{{.Os}}|{{.Architecture}}",
                image,
            ],
            PROCESS_TIMEOUT,
        )?;
        if !docker_reports_linux_amd64(rechecked.status.success(), &rechecked.stdout) {
            return Err(LauncherError::new(
                "RELEASE_IMAGE_PLATFORM_INVALID",
                "固定发布镜像不存在或不是 Linux/amd64；未继续初始化或启动产品服务。",
            ));
        }
    }
    Ok(())
}

fn release_image_references(image_lock: &ImageLock) -> [&str; 5] {
    [
        image_lock.postgres.as_str(),
        image_lock.api.as_str(),
        image_lock.egress_guard.as_str(),
        image_lock.worker.as_str(),
        image_lock.web.as_str(),
    ]
}

fn verify_compose_config(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<(), LauncherError> {
    let config = compose(
        tools,
        installation,
        &["config", "--format", "json"],
        PROCESS_TIMEOUT,
    )?;
    if !config.status.success() {
        return Err(LauncherError::new(
            "COMPOSE_CONFIG_INVALID",
            "固定 Compose 清单无法通过 Docker Compose 校验。",
        ));
    }
    validate_rendered_compose(&config.stdout, image_lock)?;
    Ok(())
}

fn verify_compose_config_for_runtime(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let config = compose_for_runtime(
        tools,
        installation,
        active_runtime,
        &["config", "--format", "json"],
        PROCESS_TIMEOUT,
    )?;
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    if !config.status.success() {
        return Err(LauncherError::new(
            "COMPOSE_CONFIG_INVALID",
            "固定 Compose 清单无法通过 Docker Compose 校验。",
        ));
    }
    validate_rendered_compose(&config.stdout, image_lock)?;
    Ok(())
}

fn configure_local_docker_endpoint(
    tools: &mut Tools,
    installation: &Installation,
) -> Result<(), LauncherError> {
    if env::var_os("DOCKER_HOST").is_some() || env::var_os("DOCKER_CONTEXT").is_some() {
        return Err(LauncherError::new(
            "REMOTE_DOCKER_CONTEXT_REJECTED",
            "检测到 DOCKER_HOST/DOCKER_CONTEXT 覆盖。V1 只允许本机 Docker Desktop Linux Engine。",
        ));
    }
    for endpoint in LOCAL_DOCKER_DESKTOP_ENDPOINTS {
        tools.docker_host = Some(OsString::from(endpoint));
        let version = docker(
            tools,
            installation,
            &["version", "--format", "{{.Server.Os}}|{{.Server.Arch}}"],
            PROCESS_TIMEOUT,
        )?;
        if docker_reports_linux_amd64(version.status.success(), &version.stdout) {
            return Ok(());
        }
    }
    tools.docker_host = None;
    Err(LauncherError::new(
        "LOCAL_DOCKER_CONTEXT_REQUIRED",
        "Docker Desktop 未在固定本机 named pipe 上提供 Linux/amd64 Engine；已拒绝用户上下文、远程或自定义 Engine。",
    ))
}

fn ensure_runtime_secrets(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
) -> Result<(), LauncherError> {
    let local_app_data = installation.app_data_root.parent().ok_or_else(|| {
        LauncherError::new(
            "LOCALAPPDATA_UNAVAILABLE",
            "Windows LOCALAPPDATA 目录结构无效。",
        )
    })?;
    platform::ensure_directory(local_app_data)?;
    create_controlled_directory(&installation.app_data_root)?;
    platform::ensure_directory(&installation.app_data_root)?;

    let sid = current_user_sid(start_tools, installation)?;
    restrict_directory_acl(start_tools, installation, &installation.app_data_root, &sid)?;
    create_controlled_directory(&installation.secret_dir)?;
    platform::ensure_directory(&installation.secret_dir)?;
    restrict_directory_acl(start_tools, installation, &installation.secret_dir, &sid)?;

    if installation.initialization_state.exists() {
        return resume_runtime_initialization(tools, start_tools, installation, &sid);
    }

    let presence = runtime_volume_presence(tools, installation)?;
    let has_marker = installation.installation_id.exists();
    let has_any_secret = runtime_secret_paths(installation)
        .iter()
        .any(|path| path.exists());
    if storage_identity_decision(presence, has_marker, has_any_secret)
        == StorageIdentityDecision::Fresh
    {
        ensure_initialization_containers_absent(tools, installation)?;
        create_initialization_state(start_tools, installation, &sid)?;
        return resume_runtime_initialization(tools, start_tools, installation, &sid);
    }

    let storage_was_existing = ensure_storage_identity(tools, start_tools, installation, &sid)?;
    ensure_existing_runtime_secrets(start_tools, installation, &sid, storage_was_existing)?;
    let installation_id = read_installation_id(&installation.installation_id)?;
    ensure_legacy_runtime_generation(start_tools, installation, &sid, &installation_id)
}

fn ensure_existing_runtime_secrets(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    storage_was_existing: bool,
) -> Result<(), LauncherError> {
    ensure_postgres_secret(start_tools, installation, sid, storage_was_existing)?;
    ensure_egress_guard_database_secret(start_tools, installation, sid, storage_was_existing)?;
    ensure_runtime_database_secret(
        start_tools,
        installation,
        sid,
        storage_was_existing,
        &installation.api_database_secret,
        "API_DATABASE_SECRET",
        "API 运行数据库密码",
    )?;
    ensure_runtime_database_secret(
        start_tools,
        installation,
        sid,
        storage_was_existing,
        &installation.worker_database_secret,
        "WORKER_DATABASE_SECRET",
        "Worker 运行数据库密码",
    )?;
    validate_database_secret_domain_separation(installation)?;
    ensure_egress_lease_creation_capability(start_tools, installation, sid, storage_was_existing)?;
    ensure_auth_secret_bundle(start_tools, installation, sid, storage_was_existing)?;
    ensure_credential_kek(start_tools, installation, sid, storage_was_existing)
}

fn runtime_secret_paths(installation: &Installation) -> [&Path; RUNTIME_SECRET_COUNT] {
    [
        installation.postgres_secret.as_path(),
        installation.egress_guard_database_secret.as_path(),
        installation.egress_lease_creation_capability.as_path(),
        installation.api_database_secret.as_path(),
        installation.worker_database_secret.as_path(),
        installation.jwt_private_key.as_path(),
        installation.jwt_public_key.as_path(),
        installation.refresh_token_hmac_key.as_path(),
        installation.idempotency_hmac_key.as_path(),
        installation.credential_kek.as_path(),
    ]
}

fn initialization_recovery_decision(
    presence: [bool; 3],
    has_installation_id: bool,
    secret_count: usize,
) -> InitializationRecoveryDecision {
    if secret_count > RUNTIME_SECRET_COUNT {
        return InitializationRecoveryDecision::Unsafe;
    }
    let volume_count = presence.iter().filter(|exists| **exists).count();
    if volume_count == 0 {
        return if has_installation_id {
            InitializationRecoveryDecision::Unsafe
        } else {
            InitializationRecoveryDecision::RegenerateSecrets
        };
    }
    if secret_count != RUNTIME_SECRET_COUNT {
        return InitializationRecoveryDecision::Unsafe;
    }
    if has_installation_id {
        if volume_count == presence.len() {
            InitializationRecoveryDecision::Finalize
        } else {
            InitializationRecoveryDecision::Unsafe
        }
    } else {
        InitializationRecoveryDecision::CompleteVolumes
    }
}

fn resume_runtime_initialization(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
) -> Result<(), LauncherError> {
    platform::ensure_regular_file(&installation.initialization_state)?;
    restrict_file_acl(
        start_tools,
        installation,
        &installation.initialization_state,
        sid,
    )?;
    let initialization_id = read_installation_id(&installation.initialization_state)?;
    ensure_initialization_containers_absent(tools, installation)?;

    let presence = runtime_volume_presence(tools, installation)?;
    validate_present_runtime_volume_identity(tools, installation, &initialization_id, presence)?;
    let secret_count = runtime_secret_paths(installation)
        .iter()
        .filter(|path| path.exists())
        .count();
    let decision = initialization_recovery_decision(
        presence,
        installation.installation_id.exists(),
        secret_count,
    );
    if decision == InitializationRecoveryDecision::Unsafe {
        return Err(LauncherError::new(
            "INITIALIZATION_RECOVERY_UNSAFE",
            "首次初始化日志与 installation-id、secret 或数据卷状态矛盾；Launcher 不会补写密钥、删除卷或猜测恢复。",
        ));
    }

    if decision == InitializationRecoveryDecision::RegenerateSecrets {
        clear_uncommitted_initialization_secrets(installation)?;
        ensure_existing_runtime_secrets(start_tools, installation, sid, false)?;
    } else {
        ensure_existing_runtime_secrets(start_tools, installation, sid, true)?;
    }
    if runtime_secret_paths(installation)
        .iter()
        .any(|path| !path.exists())
    {
        return Err(LauncherError::new(
            "INITIALIZATION_SECRET_SET_INCOMPLETE",
            "首次初始化 secret 集合未完整落盘，未创建或补写任何数据卷。",
        ));
    }

    if decision != InitializationRecoveryDecision::Finalize {
        create_missing_runtime_volumes(tools, installation, &initialization_id, presence)?;
    }
    let completed_presence = runtime_volume_presence(tools, installation)?;
    if completed_presence != [true; 3] {
        return Err(LauncherError::new(
            "RUNTIME_VOLUME_SET_INCOMPLETE",
            "首次初始化尚未完整创建三个数据卷；日志已保留供安全重试，未删除任何卷。",
        ));
    }
    validate_runtime_volume_identity(tools, installation, &initialization_id)?;

    if installation.installation_id.exists() {
        platform::ensure_regular_file(&installation.installation_id)?;
        restrict_file_acl(
            start_tools,
            installation,
            &installation.installation_id,
            sid,
        )?;
        let committed = read_installation_id(&installation.installation_id)?;
        if !constant_time_ascii_equal(&committed, &initialization_id) {
            return Err(LauncherError::new(
                "INITIALIZATION_ID_MISMATCH",
                "首次初始化日志与已提交 installation-id 不一致；Launcher 已安全阻断。",
            ));
        }
    } else {
        commit_installation_id(start_tools, installation, sid, &initialization_id)?;
    }

    ensure_legacy_runtime_generation(start_tools, installation, sid, &initialization_id)?;

    fs::remove_file(&installation.initialization_state).map_err(|_| {
        LauncherError::new(
            "INITIALIZATION_COMMIT_FAILED",
            "首次初始化已生成完整 secret 和数据卷，但无法清除受控初始化日志；服务未启动，可安全重试。",
        )
    })?;
    Ok(())
}

fn clear_uncommitted_initialization_secrets(
    installation: &Installation,
) -> Result<(), LauncherError> {
    for path in runtime_secret_paths(installation) {
        if !path.exists() {
            continue;
        }
        platform::ensure_regular_file(path)?;
        fs::remove_file(path).map_err(|_| {
            LauncherError::new(
                "INITIALIZATION_SECRET_RESET_FAILED",
                "无法清理从未被服务使用的未提交初始化 secret；Launcher 已安全阻断。",
            )
        })?;
    }
    Ok(())
}

fn ensure_initialization_containers_absent(
    tools: &Tools,
    installation: &Installation,
) -> Result<(), LauncherError> {
    let mut filters = vec![format!(
        "label=com.docker.compose.project={COMPOSE_PROJECT}"
    )];
    filters.extend(
        RUNTIME_VOLUMES
            .iter()
            .map(|(name, _)| format!("volume={name}")),
    );
    for filter in filters {
        let output = docker(
            tools,
            installation,
            &["ps", "--all", "--quiet", "--filter", &filter],
            PROCESS_TIMEOUT,
        )?;
        if !output.status.success() {
            return Err(LauncherError::new(
                "INITIALIZATION_CONTAINER_PROOF_FAILED",
                "无法证明首次初始化期间不存在 Compose/PostgreSQL 或数据卷消费者；Launcher 已安全阻断。",
            ));
        }
        if !normalize_text(&output.stdout).trim().is_empty() {
            return Err(LauncherError::new(
                "INITIALIZATION_CONTAINER_HISTORY_UNSAFE",
                "首次初始化日志仍存在，但检测到产品或数据卷容器；Launcher 不会补写密钥、补卷或自动删除容器。",
            ));
        }
    }
    Ok(())
}

fn ensure_postgres_secret(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    volume_exists: bool,
) -> Result<(), LauncherError> {
    if installation.postgres_secret.exists() {
        platform::ensure_regular_file(&installation.postgres_secret)?;
        restrict_file_acl(
            start_tools,
            installation,
            &installation.postgres_secret,
            sid,
        )?;
        validate_existing_hex_secret(
            &installation.postgres_secret,
            "POSTGRES_SECRET_INVALID",
            "PostgreSQL 密码",
        )?;
        return Ok(());
    }

    if volume_exists {
        return Err(LauncherError::new(
            "POSTGRES_SECRET_MISSING",
            "PostgreSQL 数据卷已存在，但本机密码文件缺失。为避免破坏恢复，Launcher 不会生成替代密码。",
        ));
    }

    let mut random = [0_u8; 32];
    fill_random(&mut random).map_err(|_| {
        LauncherError::new(
            "SECRET_RANDOM_FAILED",
            "Windows 安全随机数生成失败，未创建密码文件。",
        )
    })?;
    let mut secret = hex_lower_32(&random);
    random.zeroize();

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&installation.postgres_secret)
        .map_err(|_| {
            LauncherError::new(
                "SECRET_CREATE_FAILED",
                "无法以 create_new 方式创建 PostgreSQL 密码文件。",
            )
        })?;
    let write_result = file
        .write_all(&secret)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    secret.zeroize();
    if write_result.is_err() {
        let _ = fs::remove_file(&installation.postgres_secret);
        return Err(LauncherError::new(
            "SECRET_WRITE_FAILED",
            "PostgreSQL 密码文件写入失败，已清理不完整文件。",
        ));
    }
    if let Err(error) = restrict_file_acl(
        start_tools,
        installation,
        &installation.postgres_secret,
        sid,
    ) {
        let _ = fs::remove_file(&installation.postgres_secret);
        return Err(error);
    }
    Ok(())
}

fn ensure_egress_guard_database_secret(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    volume_exists: bool,
) -> Result<(), LauncherError> {
    let existed = installation.egress_guard_database_secret.exists();
    if existed {
        platform::ensure_regular_file(&installation.egress_guard_database_secret)?;
        restrict_file_acl(
            start_tools,
            installation,
            &installation.egress_guard_database_secret,
            sid,
        )?;
        validate_existing_hex_secret(
            &installation.egress_guard_database_secret,
            "EGRESS_GUARD_DATABASE_SECRET_INVALID",
            "出口守卫数据库密码",
        )?;
    } else {
        if volume_exists {
            return Err(LauncherError::new(
                "EGRESS_GUARD_DATABASE_SECRET_MISSING",
                "PostgreSQL 数据卷已存在，但出口守卫只读数据库密码缺失。Launcher 不会生成替代密码。",
            ));
        }
        let mut random = [0_u8; 32];
        fill_random(&mut random).map_err(|_| {
            LauncherError::new(
                "EGRESS_GUARD_DATABASE_SECRET_RANDOM_FAILED",
                "Windows 安全随机数生成失败，未创建出口守卫数据库密码。",
            )
        })?;
        let mut secret = hex_lower_32(&random);
        random.zeroize();
        let result = write_new_secret_file(
            &installation.egress_guard_database_secret,
            &secret,
            "EGRESS_GUARD_DATABASE_SECRET_CREATE_FAILED",
        );
        secret.zeroize();
        result?;
        if let Err(error) = restrict_file_acl(
            start_tools,
            installation,
            &installation.egress_guard_database_secret,
            sid,
        ) {
            let _ = fs::remove_file(&installation.egress_guard_database_secret);
            return Err(error);
        }
    }

    let postgres = Zeroizing::new(read_bounded_file(
        &installation.postgres_secret,
        64,
        "DATABASE_SECRET_DOMAIN_SEPARATION_FAILED",
    )?);
    let guard = Zeroizing::new(read_bounded_file(
        &installation.egress_guard_database_secret,
        64,
        "DATABASE_SECRET_DOMAIN_SEPARATION_FAILED",
    )?);
    if !independent_database_passwords_valid(&postgres, &guard) {
        if !existed {
            let _ = fs::remove_file(&installation.egress_guard_database_secret);
        }
        return Err(LauncherError::new(
            "DATABASE_SECRET_DOMAIN_SEPARATION_FAILED",
            "PostgreSQL 管理密码与出口守卫只读密码必须是两个独立的 32-byte 随机值。",
        ));
    }
    Ok(())
}

fn ensure_runtime_database_secret(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    volume_exists: bool,
    path: &Path,
    error_prefix: &str,
    purpose: &str,
) -> Result<(), LauncherError> {
    if path.exists() {
        platform::ensure_regular_file(path)?;
        restrict_file_acl(start_tools, installation, path, sid)?;
        return validate_existing_hex_secret(path, &format!("{error_prefix}_INVALID"), purpose);
    }
    if volume_exists {
        return Err(LauncherError::new(
            format!("{error_prefix}_MISSING"),
            format!("PostgreSQL 数据卷已存在，但{purpose}缺失。Launcher 不会生成替代密码。"),
        ));
    }

    let mut random = [0_u8; 32];
    fill_random(&mut random).map_err(|_| {
        LauncherError::new(
            format!("{error_prefix}_RANDOM_FAILED"),
            format!("Windows 安全随机数生成失败，未创建{purpose}。"),
        )
    })?;
    let mut secret = hex_lower_32(&random);
    random.zeroize();
    let result = write_new_secret_file(path, &secret, &format!("{error_prefix}_CREATE_FAILED"));
    secret.zeroize();
    result?;
    if let Err(error) = restrict_file_acl(start_tools, installation, path, sid) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn validate_database_secret_domain_separation(
    installation: &Installation,
) -> Result<(), LauncherError> {
    validate_database_secret_domain_separation_paths(&RuntimeSecretPaths::from_directory(
        installation.secret_dir.clone(),
    ))
}

fn validate_database_secret_domain_separation_paths(
    secrets: &RuntimeSecretPaths,
) -> Result<(), LauncherError> {
    let postgres = Zeroizing::new(read_bounded_file(
        &secrets.postgres,
        64,
        "DATABASE_SECRET_DOMAIN_SEPARATION_FAILED",
    )?);
    let guard = Zeroizing::new(read_bounded_file(
        &secrets.egress_guard_database,
        64,
        "DATABASE_SECRET_DOMAIN_SEPARATION_FAILED",
    )?);
    let api = Zeroizing::new(read_bounded_file(
        &secrets.api_database,
        64,
        "DATABASE_SECRET_DOMAIN_SEPARATION_FAILED",
    )?);
    let worker = Zeroizing::new(read_bounded_file(
        &secrets.worker_database,
        64,
        "DATABASE_SECRET_DOMAIN_SEPARATION_FAILED",
    )?);
    if !independent_database_password_set_valid(&[
        postgres.as_slice(),
        guard.as_slice(),
        api.as_slice(),
        worker.as_slice(),
    ]) {
        return Err(LauncherError::new(
            "DATABASE_SECRET_DOMAIN_SEPARATION_FAILED",
            "迁移管理员、出口守卫、API 与 Worker 必须使用四个独立的 32-byte 随机数据库密码。",
        ));
    }
    Ok(())
}

fn ensure_egress_lease_creation_capability(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    storage_was_existing: bool,
) -> Result<(), LauncherError> {
    let existed = installation.egress_lease_creation_capability.exists();
    ensure_runtime_database_secret(
        start_tools,
        installation,
        sid,
        storage_was_existing,
        &installation.egress_lease_creation_capability,
        "EGRESS_LEASE_CREATION_CAPABILITY",
        "出口租约创建能力密钥",
    )?;
    if let Err(error) = validate_egress_lease_creation_capability_domain_separation(installation) {
        if !existed {
            let _ = fs::remove_file(&installation.egress_lease_creation_capability);
        }
        return Err(error);
    }
    Ok(())
}

fn validate_egress_lease_creation_capability_domain_separation(
    installation: &Installation,
) -> Result<(), LauncherError> {
    validate_egress_lease_creation_capability_domain_separation_paths(
        &RuntimeSecretPaths::from_directory(installation.secret_dir.clone()),
    )
}

fn validate_egress_lease_creation_capability_domain_separation_paths(
    secrets: &RuntimeSecretPaths,
) -> Result<(), LauncherError> {
    let postgres = Zeroizing::new(read_bounded_file(
        &secrets.postgres,
        64,
        "EGRESS_LEASE_CREATION_CAPABILITY_DOMAIN_SEPARATION_FAILED",
    )?);
    let guard = Zeroizing::new(read_bounded_file(
        &secrets.egress_guard_database,
        64,
        "EGRESS_LEASE_CREATION_CAPABILITY_DOMAIN_SEPARATION_FAILED",
    )?);
    let api = Zeroizing::new(read_bounded_file(
        &secrets.api_database,
        64,
        "EGRESS_LEASE_CREATION_CAPABILITY_DOMAIN_SEPARATION_FAILED",
    )?);
    let worker = Zeroizing::new(read_bounded_file(
        &secrets.worker_database,
        64,
        "EGRESS_LEASE_CREATION_CAPABILITY_DOMAIN_SEPARATION_FAILED",
    )?);
    let capability = Zeroizing::new(read_bounded_file(
        &secrets.egress_lease_creation_capability,
        64,
        "EGRESS_LEASE_CREATION_CAPABILITY_DOMAIN_SEPARATION_FAILED",
    )?);
    if !independent_database_password_set_valid(&[
        postgres.as_slice(),
        guard.as_slice(),
        api.as_slice(),
        worker.as_slice(),
        capability.as_slice(),
    ]) {
        return Err(LauncherError::new(
            "EGRESS_LEASE_CREATION_CAPABILITY_DOMAIN_SEPARATION_FAILED",
            "出口租约创建能力密钥必须与四个数据库密码分别使用独立的 32-byte 随机值。",
        ));
    }
    Ok(())
}

fn ensure_auth_secret_bundle(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    volume_exists: bool,
) -> Result<(), LauncherError> {
    let paths = [
        &installation.jwt_private_key,
        &installation.jwt_public_key,
        &installation.refresh_token_hmac_key,
        &installation.idempotency_hmac_key,
    ];
    let existing = paths.iter().filter(|path| path.exists()).count();
    if existing == paths.len() {
        for path in paths {
            platform::ensure_regular_file(path)?;
            restrict_file_acl(start_tools, installation, path, sid)?;
        }
        return validate_existing_auth_secret_bundle(installation);
    }
    if existing != 0 {
        return Err(LauncherError::new(
            "AUTH_SECRET_BUNDLE_INCOMPLETE",
            "JWT/HMAC 本机密钥束不完整；Launcher 不会覆盖或补写部分密钥。",
        ));
    }
    if volume_exists {
        return Err(LauncherError::new(
            "AUTH_SECRET_BUNDLE_MISSING",
            "PostgreSQL 数据卷已存在，但 JWT/HMAC 本机密钥束缺失。为避免使既有登录状态失效，Launcher 不会生成替代密钥。",
        ));
    }

    create_auth_secret_bundle(start_tools, installation, sid)
}

fn create_auth_secret_bundle(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
) -> Result<(), LauncherError> {
    let mut seed = [0_u8; 32];
    fill_random(&mut seed).map_err(|_| {
        LauncherError::new(
            "AUTH_SECRET_RANDOM_FAILED",
            "Windows 安全随机数生成失败，未创建 JWT/HMAC 密钥束。",
        )
    })?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let verifying_key = signing_key.verifying_key();
    let private_pem = signing_key.to_pkcs8_pem(LineEnding::LF).map_err(|_| {
        LauncherError::new(
            "AUTH_SECRET_ENCODE_FAILED",
            "无法编码 Ed25519 PKCS#8 私钥，未创建密钥束。",
        )
    })?;
    let public_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| {
            LauncherError::new(
                "AUTH_SECRET_ENCODE_FAILED",
                "无法编码 Ed25519 SPKI 公钥，未创建密钥束。",
            )
        })?;
    let mut refresh_hmac_key = [0_u8; 32];
    if fill_random(&mut refresh_hmac_key).is_err() {
        refresh_hmac_key.zeroize();
        return Err(LauncherError::new(
            "AUTH_SECRET_RANDOM_FAILED",
            "Windows 安全随机数生成失败，未创建 JWT/HMAC 密钥束。",
        ));
    }
    let mut idempotency_hmac_key = [0_u8; 32];
    if fill_random(&mut idempotency_hmac_key).is_err() {
        refresh_hmac_key.zeroize();
        idempotency_hmac_key.zeroize();
        return Err(LauncherError::new(
            "AUTH_SECRET_RANDOM_FAILED",
            "Windows 安全随机数生成失败，未创建 JWT/HMAC 密钥束。",
        ));
    }
    if !independent_hmac_keys_valid(&refresh_hmac_key, &idempotency_hmac_key) {
        refresh_hmac_key.zeroize();
        idempotency_hmac_key.zeroize();
        return Err(LauncherError::new(
            "AUTH_SECRET_DOMAIN_SEPARATION_FAILED",
            "两类 HMAC 密钥未实现独立域分离，已拒绝创建密钥束。",
        ));
    }

    let mut created = Vec::with_capacity(4);
    let result = (|| {
        write_new_secret_file(
            &installation.jwt_private_key,
            private_pem.as_bytes(),
            "AUTH_SECRET_CREATE_FAILED",
        )?;
        created.push(installation.jwt_private_key.clone());
        restrict_file_acl(
            start_tools,
            installation,
            &installation.jwt_private_key,
            sid,
        )?;

        write_new_secret_file(
            &installation.jwt_public_key,
            public_pem.as_bytes(),
            "AUTH_SECRET_CREATE_FAILED",
        )?;
        created.push(installation.jwt_public_key.clone());
        restrict_file_acl(start_tools, installation, &installation.jwt_public_key, sid)?;

        write_new_secret_file(
            &installation.refresh_token_hmac_key,
            &refresh_hmac_key,
            "AUTH_SECRET_CREATE_FAILED",
        )?;
        created.push(installation.refresh_token_hmac_key.clone());
        restrict_file_acl(
            start_tools,
            installation,
            &installation.refresh_token_hmac_key,
            sid,
        )?;

        write_new_secret_file(
            &installation.idempotency_hmac_key,
            &idempotency_hmac_key,
            "AUTH_SECRET_CREATE_FAILED",
        )?;
        created.push(installation.idempotency_hmac_key.clone());
        restrict_file_acl(
            start_tools,
            installation,
            &installation.idempotency_hmac_key,
            sid,
        )?;
        validate_existing_auth_secret_bundle(installation)
    })();
    refresh_hmac_key.zeroize();
    idempotency_hmac_key.zeroize();
    if let Err(error) = result {
        for path in created {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(())
}

fn write_new_secret_file(path: &Path, value: &[u8], error_code: &str) -> Result<(), LauncherError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| LauncherError::new(error_code, "无法以 create_new 方式创建本机密钥文件。"))?;
    if file
        .write_all(value)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(LauncherError::new(
            error_code,
            "本机密钥文件写入失败，已清理不完整文件。",
        ));
    }
    Ok(())
}

fn read_runtime_generation(path: &Path) -> Result<RuntimeGeneration, LauncherError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_MISSING",
                "活动运行代际指针不存在；请先用 Launcher 完成安全迁移。",
            ));
        }
        Err(_) => {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_INVALID",
                "无法安全检查活动运行代际指针。",
            ));
        }
        Ok(_) => platform::ensure_regular_file(path).map_err(|_| {
            LauncherError::new(
                "RUNTIME_GENERATION_INVALID",
                "活动运行代际指针不是受控普通文件。",
            )
        })?,
    }
    let bytes = read_bounded_file(path, 16 * 1024, "RUNTIME_GENERATION_INVALID")?;
    RuntimeGeneration::parse(&bytes)
}

// The active pointer is the only source of runtime identity after initialization.
// The root installation-id remains an input solely for an existing LEGACY object
// set, which is intentionally migrated without copying or renaming it. FRESH and
// RESTORE must never read a second, root-level "current" identity.
fn load_active_runtime_snapshot(
    installation: &Installation,
) -> Result<ActiveRuntimeSnapshot, LauncherError> {
    platform::ensure_tree_no_reparse(&installation.app_data_root).map_err(|_| {
        LauncherError::new(
            "RUNTIME_GENERATION_INVALID",
            "无法验证活动运行代际根目录；检测到缺失目录、非本地路径或 reparse point。",
        )
    })?;
    let generation = read_runtime_generation(&installation.runtime_generation)?;
    if generation.source == "LEGACY" {
        let legacy_installation_id = read_installation_id(&installation.installation_id)?;
        if !constant_time_ascii_equal(&generation.installation_id, &legacy_installation_id) {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_IDENTITY_MISMATCH",
                "活动 LEGACY 运行代际与旧式 installation-id 不一致；Launcher 已安全阻断。",
            ));
        }
    }
    ActiveRuntimeSnapshot::from_generation(&installation.app_data_root, generation)
}

fn require_active_runtime_snapshot_unchanged(
    installation: &Installation,
    expected: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    let actual = load_active_runtime_snapshot(installation)?;
    if actual != *expected {
        return Err(LauncherError::new(
            "RUNTIME_GENERATION_CHANGED_DURING_ACTION",
            "活动运行代际在操作期间发生变化；Launcher 已拒绝拼接 secret、数据卷或 Compose 身份。",
        ));
    }
    Ok(())
}

fn load_verified_active_runtime_snapshot(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
) -> Result<ActiveRuntimeSnapshot, LauncherError> {
    platform::ensure_tree_no_reparse(&installation.app_data_root).map_err(|_| {
        LauncherError::new(
            "RUNTIME_GENERATION_INVALID",
            "无法验证活动运行代际根目录；检测到缺失目录、非本地路径或 reparse point。",
        )
    })?;
    restrict_directory_acl(start_tools, installation, &installation.app_data_root, sid)?;
    platform::ensure_tree_no_reparse(&installation.app_data_root).map_err(|_| {
        LauncherError::new(
            "RUNTIME_GENERATION_INVALID",
            "活动运行代际根目录在 ACL 复核期间发生变化。",
        )
    })?;
    platform::ensure_regular_file(&installation.runtime_generation).map_err(|_| {
        LauncherError::new(
            "RUNTIME_GENERATION_INVALID",
            "活动运行代际指针不是受控普通文件。",
        )
    })?;
    restrict_file_acl(
        start_tools,
        installation,
        &installation.runtime_generation,
        sid,
    )?;
    load_active_runtime_snapshot(installation)
}

fn ensure_legacy_runtime_generation(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    installation_id: &str,
) -> Result<(), LauncherError> {
    if !is_secret_bytes(installation_id.as_bytes()) {
        return Err(LauncherError::new(
            "INSTALLATION_ID_INVALID",
            "无法用格式无效的 installation-id 提交运行代际。",
        ));
    }
    if installation.runtime_generation.exists() {
        platform::ensure_regular_file(&installation.runtime_generation)?;
        let generation = read_runtime_generation(&installation.runtime_generation)?;
        if generation.source != "LEGACY"
            || !constant_time_ascii_equal(&generation.installation_id, installation_id)
        {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_IDENTITY_MISMATCH",
                "活动运行代际不是当前完整旧式对象集合；Launcher 不会拼接或覆盖它。",
            ));
        }
        restrict_file_acl(
            start_tools,
            installation,
            &installation.runtime_generation,
            sid,
        )?;
        let rechecked = read_runtime_generation(&installation.runtime_generation)?;
        if rechecked != generation {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_CHANGED_DURING_CHECK",
                "活动运行代际在 ACL 核验期间发生变化；Launcher 已安全阻断。",
            ));
        }
        return Ok(());
    }

    let generation_id = random_runtime_generation_id()?;
    let generation = RuntimeGeneration::legacy(
        generation_id.clone(),
        installation_id.to_owned(),
        current_utc_timestamp(SystemTime::now())?,
    )?;
    let encoded = generation.to_bytes()?;
    let pending = installation
        .app_data_root
        .join(format!(".runtime-generation-{generation_id}.pending"));
    write_new_secret_file(
        &pending,
        &encoded,
        "RUNTIME_GENERATION_PENDING_CREATE_FAILED",
    )?;

    let prepared = (|| {
        restrict_file_acl(start_tools, installation, &pending, sid)?;
        let parsed = read_runtime_generation(&pending)?;
        if parsed != generation {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_PENDING_INVALID",
                "运行代际 pending 文件回读不一致；未提交活动指针。",
            ));
        }
        platform::move_new_write_through(&pending, &installation.runtime_generation)?;
        let committed = read_runtime_generation(&installation.runtime_generation)?;
        if committed != generation {
            return Err(LauncherError::new(
                "RUNTIME_GENERATION_COMMIT_INVALID",
                "活动运行代际指针提交后回读不一致；服务未启动。",
            ));
        }
        Ok(())
    })();
    if prepared.is_err() && pending.exists() {
        let _ = fs::remove_file(&pending);
    }
    prepared
}

fn random_runtime_generation_id() -> Result<String, LauncherError> {
    let mut random = Zeroizing::new([0_u8; 16]);
    fill_random(&mut *random).map_err(|_| {
        LauncherError::new(
            "RUNTIME_GENERATION_RANDOM_FAILED",
            "Windows 安全随机数生成失败，未创建运行代际。",
        )
    })?;
    Ok(hex_lower(&*random))
}

fn current_utc_timestamp(now: SystemTime) -> Result<String, LauncherError> {
    let elapsed = now.duration_since(UNIX_EPOCH).map_err(|_| {
        LauncherError::new(
            "RUNTIME_GENERATION_TIME_INVALID",
            "系统 UTC 时间早于 Unix epoch，未创建运行代际。",
        )
    })?;
    let seconds = i64::try_from(elapsed.as_secs()).map_err(|_| {
        LauncherError::new(
            "RUNTIME_GENERATION_TIME_INVALID",
            "系统 UTC 时间超出支持范围，未创建运行代际。",
        )
    })?;
    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_date_from_unix_days(days);
    if !(2000..=9999).contains(&year) {
        return Err(LauncherError::new(
            "RUNTIME_GENERATION_TIME_INVALID",
            "系统 UTC 年份超出运行代际契约范围。",
        ));
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_date_from_unix_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn validate_existing_auth_secret_bundle(installation: &Installation) -> Result<(), LauncherError> {
    validate_existing_auth_secret_bundle_paths(&RuntimeSecretPaths::from_directory(
        installation.secret_dir.clone(),
    ))
}

fn validate_existing_auth_secret_bundle_paths(
    secrets: &RuntimeSecretPaths,
) -> Result<(), LauncherError> {
    let private_bytes = Zeroizing::new(read_bounded_file(
        &secrets.jwt_private_key,
        4096,
        "AUTH_SECRET_BUNDLE_INVALID",
    )?);
    let public_bytes =
        read_bounded_file(&secrets.jwt_public_key, 4096, "AUTH_SECRET_BUNDLE_INVALID")?;
    let refresh_hmac_bytes = Zeroizing::new(read_bounded_file(
        &secrets.refresh_token_hmac_key,
        32,
        "AUTH_SECRET_BUNDLE_INVALID",
    )?);
    let idempotency_hmac_bytes = Zeroizing::new(read_bounded_file(
        &secrets.idempotency_hmac_key,
        32,
        "AUTH_SECRET_BUNDLE_INVALID",
    )?);

    let validation = (|| {
        if !independent_hmac_keys_valid(&refresh_hmac_bytes, &idempotency_hmac_bytes) {
            return Err(());
        }
        let private_pem = std::str::from_utf8(&private_bytes).map_err(|_| ())?;
        let public_pem = std::str::from_utf8(&public_bytes).map_err(|_| ())?;
        let signing_key = SigningKey::from_pkcs8_pem(private_pem).map_err(|_| ())?;
        let verifying_key = VerifyingKey::from_public_key_pem(public_pem).map_err(|_| ())?;
        if signing_key.verifying_key() != verifying_key {
            return Err(());
        }
        Ok(())
    })();
    validation.map_err(|_| {
        LauncherError::new(
            "AUTH_SECRET_BUNDLE_INVALID",
            "现有 JWT/HMAC 密钥束格式无效、公私钥不匹配或两类 HMAC 未独立；Launcher 不会覆盖它。",
        )
    })
}

fn ensure_credential_kek(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    volume_exists: bool,
) -> Result<(), LauncherError> {
    if installation.credential_kek.exists() {
        platform::ensure_regular_file(&installation.credential_kek)?;
        restrict_file_acl(start_tools, installation, &installation.credential_kek, sid)?;
        return validate_existing_credential_kek(installation);
    }
    if volume_exists {
        return Err(LauncherError::new(
            "CREDENTIAL_KEK_MISSING",
            "PostgreSQL 数据卷已存在，但凭据 KEK 缺失。为避免永久失去既有数据源凭据，Launcher 不会生成替代密钥。",
        ));
    }

    let mut credential_kek = Zeroizing::new([0_u8; 32]);
    fill_random(&mut *credential_kek).map_err(|_| {
        LauncherError::new(
            "CREDENTIAL_KEK_RANDOM_FAILED",
            "Windows 安全随机数生成失败，未创建凭据 KEK。",
        )
    })?;
    let refresh_hmac = Zeroizing::new(read_bounded_file(
        &installation.refresh_token_hmac_key,
        32,
        "CREDENTIAL_KEK_INVALID",
    )?);
    let idempotency_hmac = Zeroizing::new(read_bounded_file(
        &installation.idempotency_hmac_key,
        32,
        "CREDENTIAL_KEK_INVALID",
    )?);
    if !independent_credential_kek_valid(&*credential_kek, &refresh_hmac, &idempotency_hmac) {
        return Err(LauncherError::new(
            "CREDENTIAL_KEK_DOMAIN_SEPARATION_FAILED",
            "凭据 KEK 与认证 HMAC 密钥未实现独立域分离，已拒绝创建。",
        ));
    }
    let result = (|| {
        write_new_secret_file(
            &installation.credential_kek,
            &*credential_kek,
            "CREDENTIAL_KEK_CREATE_FAILED",
        )?;
        restrict_file_acl(start_tools, installation, &installation.credential_kek, sid)?;
        validate_existing_credential_kek(installation)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&installation.credential_kek);
        return Err(error);
    }
    Ok(())
}

fn validate_existing_credential_kek(installation: &Installation) -> Result<(), LauncherError> {
    validate_existing_credential_kek_paths(&RuntimeSecretPaths::from_directory(
        installation.secret_dir.clone(),
    ))
}

fn validate_existing_credential_kek_paths(
    secrets: &RuntimeSecretPaths,
) -> Result<(), LauncherError> {
    let credential_kek = Zeroizing::new(read_bounded_file(
        &secrets.credential_kek,
        32,
        "CREDENTIAL_KEK_INVALID",
    )?);
    let refresh_hmac = Zeroizing::new(read_bounded_file(
        &secrets.refresh_token_hmac_key,
        32,
        "CREDENTIAL_KEK_INVALID",
    )?);
    let idempotency_hmac = Zeroizing::new(read_bounded_file(
        &secrets.idempotency_hmac_key,
        32,
        "CREDENTIAL_KEK_INVALID",
    )?);
    if !independent_credential_kek_valid(&credential_kek, &refresh_hmac, &idempotency_hmac) {
        return Err(LauncherError::new(
            "CREDENTIAL_KEK_INVALID",
            "现有凭据 KEK 必须恰好 32 bytes 且独立于认证 HMAC 密钥；Launcher 不会覆盖它。",
        ));
    }
    Ok(())
}

fn validate_active_runtime_secret_set(
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    platform::ensure_tree_no_reparse(&active_runtime.secrets.directory)?;
    platform::ensure_directory(&active_runtime.secrets.directory)?;
    for path in active_runtime.secrets.all() {
        platform::ensure_regular_file(path)?;
    }
    validate_existing_hex_secret(
        &active_runtime.secrets.postgres,
        "POSTGRES_SECRET_INVALID",
        "PostgreSQL 密码",
    )?;
    validate_existing_hex_secret(
        &active_runtime.secrets.egress_guard_database,
        "EGRESS_GUARD_DATABASE_SECRET_INVALID",
        "出口守卫数据库密码",
    )?;
    validate_existing_hex_secret(
        &active_runtime.secrets.api_database,
        "API_DATABASE_SECRET_INVALID",
        "API 运行数据库密码",
    )?;
    validate_existing_hex_secret(
        &active_runtime.secrets.worker_database,
        "WORKER_DATABASE_SECRET_INVALID",
        "Worker 运行数据库密码",
    )?;
    validate_existing_hex_secret(
        &active_runtime.secrets.egress_lease_creation_capability,
        "EGRESS_LEASE_CREATION_CAPABILITY_INVALID",
        "出口租约创建能力密钥",
    )?;
    validate_database_secret_domain_separation_paths(&active_runtime.secrets)?;
    validate_egress_lease_creation_capability_domain_separation_paths(&active_runtime.secrets)?;
    validate_existing_auth_secret_bundle_paths(&active_runtime.secrets)?;
    validate_existing_credential_kek_paths(&active_runtime.secrets)
}

fn verify_active_runtime_secret_set(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    platform::ensure_tree_no_reparse(&active_runtime.secrets.directory)?;
    platform::ensure_directory(&active_runtime.secrets.directory)?;
    restrict_directory_acl(
        start_tools,
        installation,
        &active_runtime.secrets.directory,
        sid,
    )?;
    for path in active_runtime.secrets.all() {
        platform::ensure_regular_file(path)?;
        restrict_file_acl(start_tools, installation, path, sid)?;
    }
    validate_active_runtime_secret_set(active_runtime)
}

fn create_controlled_directory(path: &Path) -> Result<(), LauncherError> {
    match fs::symlink_metadata(path) {
        Ok(_) => platform::ensure_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| {
                LauncherError::new(
                    "SECRET_DIRECTORY_CREATE_FAILED",
                    "无法创建本机 secret 受控目录。",
                )
            })?;
            platform::ensure_directory(path)
        }
        Err(_) => Err(LauncherError::new(
            "SECRET_DIRECTORY_CREATE_FAILED",
            "无法检查本机 secret 受控目录。",
        )),
    }
}

fn validate_existing_hex_secret(
    path: &Path,
    error_code: &str,
    purpose: &str,
) -> Result<(), LauncherError> {
    let metadata = fs::metadata(path)
        .map_err(|_| LauncherError::new(error_code, format!("无法读取现有{purpose}文件。")))?;
    if metadata.len() != 64 {
        return Err(LauncherError::new(
            error_code,
            format!("现有{purpose}文件格式无效；Launcher 不会覆盖它。"),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| LauncherError::new(error_code, format!("无法读取现有{purpose}文件。")))?;
    let mut secret = Vec::with_capacity(65);
    file.take(65)
        .read_to_end(&mut secret)
        .map_err(|_| LauncherError::new(error_code, format!("无法验证现有{purpose}文件。")))?;
    let valid = is_secret_bytes(&secret);
    secret.zeroize();
    if !valid {
        return Err(LauncherError::new(
            error_code,
            format!("现有{purpose}文件格式无效；Launcher 不会覆盖它。"),
        ));
    }
    Ok(())
}

fn ensure_storage_identity(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
) -> Result<bool, LauncherError> {
    let presence = runtime_volume_presence(tools, installation)?;
    let has_marker = installation.installation_id.exists();
    let has_any_secret = runtime_secret_paths(installation)
        .iter()
        .any(|path| path.exists());
    match storage_identity_decision(presence, has_marker, has_any_secret) {
        StorageIdentityDecision::IncompleteVolumes => {
            return Err(LauncherError::new(
                "RUNTIME_VOLUME_SET_INCOMPLETE",
                "三个运行数据卷必须成组存在；检测到部分缺失，Launcher 已拒绝创建空替代卷。",
            ));
        }
        StorageIdentityDecision::IdentityLost => {
            return Err(LauncherError::new(
                "RUNTIME_VOLUME_IDENTITY_LOST",
                "本机安装身份或密钥仍存在，但三个 Docker 数据卷均缺失。可能发生 Docker reset；Launcher 不会静默创建空库。",
            ));
        }
        StorageIdentityDecision::MarkerMissing => {
            return Err(LauncherError::new(
                "INSTALLATION_ID_MISSING",
                "三个 Docker 数据卷已存在，但本机 installation-id 缺失；Launcher 无法证明卷归属。",
            ));
        }
        StorageIdentityDecision::Fresh => {
            return Err(LauncherError::new(
                "INITIALIZATION_STATE_MISSING",
                "全新安装必须先建立受控初始化日志；Launcher 已拒绝旧式非原子初始化路径。",
            ));
        }
        StorageIdentityDecision::Existing => {}
    }
    platform::ensure_regular_file(&installation.installation_id)?;
    restrict_file_acl(
        start_tools,
        installation,
        &installation.installation_id,
        sid,
    )?;
    let installation_id = read_installation_id(&installation.installation_id)?;
    validate_runtime_volume_identity(tools, installation, &installation_id)?;
    Ok(true)
}

fn storage_identity_decision(
    presence: [bool; 3],
    has_marker: bool,
    has_any_secret: bool,
) -> StorageIdentityDecision {
    let existing_count = presence.iter().filter(|exists| **exists).count();
    if existing_count != 0 && existing_count != presence.len() {
        return StorageIdentityDecision::IncompleteVolumes;
    }
    if existing_count == 0 {
        return if has_marker || has_any_secret {
            StorageIdentityDecision::IdentityLost
        } else {
            StorageIdentityDecision::Fresh
        };
    }
    if has_marker {
        StorageIdentityDecision::Existing
    } else {
        StorageIdentityDecision::MarkerMissing
    }
}

fn runtime_volume_presence(
    tools: &Tools,
    installation: &Installation,
) -> Result<[bool; 3], LauncherError> {
    let mut presence = [false; 3];
    for (index, (name, _)) in RUNTIME_VOLUMES.iter().enumerate() {
        let filter = format!("name={name}");
        let output = docker(
            tools,
            installation,
            &["volume", "ls", "--quiet", "--filter", &filter],
            PROCESS_TIMEOUT,
        )?;
        if !output.status.success() {
            return Err(LauncherError::new(
                "DOCKER_VOLUME_CHECK_FAILED",
                "无法完整核验三个运行数据卷；Launcher 不会生成新身份或密钥。",
            ));
        }
        presence[index] = normalize_text(&output.stdout)
            .lines()
            .any(|line| line.trim() == *name);
    }
    Ok(presence)
}

fn create_initialization_state(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
) -> Result<(), LauncherError> {
    let mut random = Zeroizing::new([0_u8; 32]);
    fill_random(&mut *random).map_err(|_| {
        LauncherError::new(
            "INSTALLATION_ID_RANDOM_FAILED",
            "Windows 安全随机数生成失败，未创建首次初始化日志。",
        )
    })?;
    let mut installation_id = Zeroizing::new(hex_lower_32(&random));
    write_new_secret_file(
        &installation.initialization_state,
        &installation_id[..],
        "INITIALIZATION_STATE_CREATE_FAILED",
    )?;
    if let Err(error) = restrict_file_acl(
        start_tools,
        installation,
        &installation.initialization_state,
        sid,
    ) {
        installation_id.zeroize();
        let _ = fs::remove_file(&installation.initialization_state);
        return Err(error);
    }
    read_installation_id(&installation.initialization_state)?;
    Ok(())
}

fn commit_installation_id(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
    initialization_id: &str,
) -> Result<(), LauncherError> {
    if !is_secret_bytes(initialization_id.as_bytes()) {
        return Err(LauncherError::new(
            "INSTALLATION_ID_INVALID",
            "首次初始化日志中的 installation-id 格式无效。",
        ));
    }
    write_new_secret_file(
        &installation.installation_id,
        initialization_id.as_bytes(),
        "INSTALLATION_ID_CREATE_FAILED",
    )?;
    if let Err(error) = restrict_file_acl(
        start_tools,
        installation,
        &installation.installation_id,
        sid,
    ) {
        let _ = fs::remove_file(&installation.installation_id);
        return Err(error);
    }
    let committed = read_installation_id(&installation.installation_id)?;
    if !constant_time_ascii_equal(&committed, initialization_id) {
        let _ = fs::remove_file(&installation.installation_id);
        return Err(LauncherError::new(
            "INSTALLATION_ID_COMMIT_FAILED",
            "提交的 installation-id 与首次初始化日志不一致；服务未启动。",
        ));
    }
    Ok(())
}

fn read_installation_id(path: &Path) -> Result<String, LauncherError> {
    let mut bytes = read_bounded_file(path, 64, "INSTALLATION_ID_INVALID")?;
    if !is_secret_bytes(&bytes) {
        bytes.zeroize();
        return Err(LauncherError::new(
            "INSTALLATION_ID_INVALID",
            "installation-id 必须是 64 bytes 小写十六进制且无换行。",
        ));
    }
    let value = String::from_utf8(bytes.clone())
        .map_err(|_| LauncherError::new("INSTALLATION_ID_INVALID", "installation-id 编码无效。"))?;
    bytes.zeroize();
    Ok(value)
}

fn create_missing_runtime_volumes(
    tools: &Tools,
    installation: &Installation,
    installation_id: &str,
    presence: [bool; 3],
) -> Result<(), LauncherError> {
    for ((name, role), exists) in RUNTIME_VOLUMES.iter().zip(presence) {
        if exists {
            continue;
        }
        let identity_label = format!("{VOLUME_IDENTITY_LABEL}={installation_id}");
        let role_label = format!("{VOLUME_ROLE_LABEL}={role}");
        let output = docker(
            tools,
            installation,
            &[
                "volume",
                "create",
                "--label",
                &identity_label,
                "--label",
                &role_label,
                *name,
            ],
            PROCESS_TIMEOUT,
        )?;
        if !output.status.success() || normalize_text(&output.stdout).trim() != *name {
            return Err(LauncherError::new(
                "RUNTIME_VOLUME_CREATE_FAILED",
                "无法以受控 installation-id 创建完整运行数据卷；初始化日志已保留供安全重试，Launcher 不会删除已有卷。",
            ));
        }
    }
    Ok(())
}

fn validate_runtime_volume_identity(
    tools: &Tools,
    installation: &Installation,
    installation_id: &str,
) -> Result<(), LauncherError> {
    validate_present_runtime_volume_identity(tools, installation, installation_id, [true; 3])
}

fn active_runtime_volume_contract(
    installation: &Installation,
) -> Result<ActiveRuntimeVolumeContract, LauncherError> {
    Ok(load_active_runtime_snapshot(installation)?.volume_contract())
}

fn validate_active_runtime_volume_contract(
    tools: &Tools,
    installation: &Installation,
    contract: &ActiveRuntimeVolumeContract,
) -> Result<(), LauncherError> {
    if !is_secret_bytes(contract.installation_id.as_bytes()) {
        return Err(LauncherError::new(
            "INSTALLATION_ID_INVALID",
            "installation-id 格式无效。",
        ));
    }
    for (name, role) in [
        (contract.names.postgres.as_str(), "postgres-data"),
        (contract.names.logs.as_str(), "log-data"),
        (contract.names.workspace.as_str(), "workspace-data"),
    ] {
        let output = docker(
            tools,
            installation,
            &[
                "volume",
                "inspect",
                "--format",
                RUNTIME_VOLUME_INSPECT_FORMAT,
                name,
            ],
            PROCESS_TIMEOUT,
        )?;
        if !output.status.success()
            || validate_runtime_volume_inspection(
                &output.stdout,
                name,
                &contract.installation_id,
                role,
            )
            .is_err()
        {
            return Err(LauncherError::new(
                "RUNTIME_VOLUME_IDENTITY_MISMATCH",
                "活动运行代际的数据卷名称、local driver/options 或 installation-id/角色标签与本机身份不一致，已拒绝挂载。",
            ));
        }
    }
    Ok(())
}

fn validate_runtime_volume_inspection(
    output: &[u8],
    expected_name: &str,
    expected_installation_id: &str,
    expected_role: &str,
) -> Result<(), LauncherError> {
    if output.len() > 16 * 1024 {
        return Err(LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷 inspect 输出长度无效。",
        ));
    }
    let output = std::str::from_utf8(output).map_err(|_| {
        LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷 inspect 输出不是有效 UTF-8。",
        )
    })?;
    if output.contains(['\r', '\0']) {
        return Err(LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷 inspect 输出包含不允许的控制字符。",
        ));
    }
    let output = output.strip_suffix('\n').unwrap_or(output);
    if output.is_empty() || output.contains('\n') {
        return Err(LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷 inspect 输出行数无效。",
        ));
    }
    let fields = output.split('\t').collect::<Vec<_>>();
    if fields.len() != 4 {
        return Err(LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷 inspect 输出字段无效。",
        ));
    }
    let name = serde_json::from_str::<String>(fields[0]).map_err(|_| {
        LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷 inspect 名称无效。",
        )
    })?;
    let driver = serde_json::from_str::<String>(fields[1]).map_err(|_| {
        LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷 inspect driver 无效。",
        )
    })?;
    let options =
        serde_json::from_str::<Option<BTreeMap<String, String>>>(fields[2]).map_err(|_| {
            LauncherError::new(
                "RUNTIME_VOLUME_IDENTITY_MISMATCH",
                "运行数据卷 inspect options 无效。",
            )
        })?;
    let labels = serde_json::from_str::<BTreeMap<String, String>>(fields[3]).map_err(|_| {
        LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷 inspect 标签无效。",
        )
    })?;
    if name != expected_name
        || driver != "local"
        || options.is_some_and(|options| !options.is_empty())
        || labels.get(VOLUME_IDENTITY_LABEL).map(String::as_str) != Some(expected_installation_id)
        || labels.get(VOLUME_ROLE_LABEL).map(String::as_str) != Some(expected_role)
    {
        return Err(LauncherError::new(
            "RUNTIME_VOLUME_IDENTITY_MISMATCH",
            "运行数据卷不是当前本机 local-volume identity。",
        ));
    }
    Ok(())
}

// Docker Desktop can place its VHD and named-volume filesystem on a disk unrelated to
// `%LOCALAPPDATA%`. This runs only after the five release images are locally present and only
// against the authenticated current generation. It mounts the product volumes read-only at fixed
// paths and executes a release-locked worker image without network or secrets. Its named helper
// identity gives the timeout/error path an immutable-ID cleanup target rather than trusting --rm.
fn ensure_docker_storage_capacity(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<(), LauncherError> {
    let volume_contract = active_runtime_volume_contract(installation)?;
    validate_active_runtime_volume_contract(tools, installation, &volume_contract)?;
    let helper = storage_probe_helper_container(&volume_contract);
    let arguments =
        docker_storage_probe_arguments(&volume_contract.names, &image_lock.worker, &helper)?;
    run_named_container_with_cleanup(
        tools,
        installation,
        &helper,
        &arguments,
        PROCESS_TIMEOUT,
        |output| {
            platform::ensure_docker_storage_capacity_probe(output.status.success(), &output.stdout)
        },
    )
}

fn storage_probe_helper_container(contract: &ActiveRuntimeVolumeContract) -> HelperContainer {
    helper_container_identity(
        DOCKER_STORAGE_PROBE_HELPER_ROLE,
        &[
            &contract.installation_id,
            &contract.names.postgres,
            &contract.names.logs,
            &contract.names.workspace,
        ],
    )
}

fn docker_storage_probe_arguments(
    volume_names: &RuntimeVolumeNames,
    worker_image: &str,
    helper: &HelperContainer,
) -> Result<Vec<OsString>, LauncherError> {
    let mut arguments = vec![
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--pull=never"),
        OsString::from("--name"),
        OsString::from(&helper.name),
        OsString::from("--label"),
        OsString::from(format!("{HELPER_CONTAINER_ROLE_LABEL}={}", helper.role)),
        OsString::from("--label"),
        OsString::from(format!("{HELPER_CONTAINER_ID_LABEL}={}", helper.opaque_id)),
        OsString::from("--network"),
        OsString::from("none"),
        OsString::from("--read-only"),
        // PostgreSQL may make its volume root 0700 for its own UID. This probe gets only
        // DAC_READ_SEARCH, not write or network capability, so its fixed statvfs script can
        // traverse all three read-only mount roots without assuming shared ownership. On Linux
        // that capability can also bypass ordinary file-read and directory-search checks, so it
        // is not a confidentiality boundary: the exact digest, fixed script and no-network/no-
        // secret contract are all part of the probe's trusted computing base.
        OsString::from("--user"),
        OsString::from("0:0"),
        OsString::from("--cap-drop"),
        OsString::from("ALL"),
        OsString::from("--cap-add"),
        OsString::from("DAC_READ_SEARCH"),
        OsString::from("--security-opt"),
        OsString::from("no-new-privileges:true"),
        OsString::from("--pids-limit"),
        OsString::from("16"),
        OsString::from("--memory"),
        OsString::from("64m"),
        OsString::from("--cpus"),
        OsString::from("0.25"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp:rw,noexec,nosuid,size=4m"),
    ];
    for mount in platform::DOCKER_STORAGE_PROBE_MOUNTS {
        let source = match mount.role {
            "postgres-data" => &volume_names.postgres,
            "log-data" => &volume_names.logs,
            "workspace-data" => &volume_names.workspace,
            _ => {
                return Err(LauncherError::new(
                    "DOCKER_STORAGE_PROBE_CONTRACT_INVALID",
                    "Docker 数据卷容量探测的固定角色契约无效；Launcher 已安全阻断。",
                ));
            }
        };
        arguments.push(OsString::from("--mount"));
        arguments.push(OsString::from(format!(
            "type=volume,source={source},target={},readonly,volume-nocopy",
            mount.target_path
        )));
    }
    arguments.extend([
        OsString::from("--entrypoint"),
        OsString::from("python"),
        OsString::from(worker_image),
        OsString::from("-c"),
        OsString::from(platform::DOCKER_STORAGE_PROBE_SCRIPT),
    ]);
    Ok(arguments)
}

fn validate_present_runtime_volume_identity(
    tools: &Tools,
    installation: &Installation,
    installation_id: &str,
    presence: [bool; 3],
) -> Result<(), LauncherError> {
    if !is_secret_bytes(installation_id.as_bytes()) {
        return Err(LauncherError::new(
            "INSTALLATION_ID_INVALID",
            "installation-id 格式无效。",
        ));
    }
    for ((name, role), exists) in RUNTIME_VOLUMES.iter().zip(presence) {
        if !exists {
            continue;
        }
        let output = docker(
            tools,
            installation,
            &[
                "volume",
                "inspect",
                "--format",
                RUNTIME_VOLUME_INSPECT_FORMAT,
                *name,
            ],
            PROCESS_TIMEOUT,
        )?;
        if !output.status.success()
            || validate_runtime_volume_inspection(&output.stdout, name, installation_id, role)
                .is_err()
        {
            return Err(LauncherError::new(
                "RUNTIME_VOLUME_IDENTITY_MISMATCH",
                "运行数据卷的名称、local driver/options 或 installation-id/角色标签与本机安装身份不一致，已拒绝挂载。",
            ));
        }
    }
    Ok(())
}

fn current_user_sid(
    tools: &StartTools,
    installation: &Installation,
) -> Result<String, LauncherError> {
    let output = run_process(
        &tools.whoami,
        &[
            OsString::from("/user"),
            OsString::from("/fo"),
            OsString::from("csv"),
            OsString::from("/nh"),
        ],
        &[],
        &installation.install_dir,
        PROCESS_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(LauncherError::new(
            "WINDOWS_IDENTITY_UNAVAILABLE",
            "无法读取当前 Windows 用户 SID。",
        ));
    }
    let text = normalize_text(&output.stdout);
    extract_sid(&text).ok_or_else(|| {
        LauncherError::new(
            "WINDOWS_IDENTITY_UNAVAILABLE",
            "当前 Windows 用户 SID 格式无效。",
        )
    })
}

fn restrict_directory_acl(
    tools: &StartTools,
    installation: &Installation,
    path: &Path,
    sid: &str,
) -> Result<(), LauncherError> {
    rebuild_and_verify_acl(tools, installation, path, sid, "Directory")
}

fn restrict_file_acl(
    tools: &StartTools,
    installation: &Installation,
    path: &Path,
    sid: &str,
) -> Result<(), LauncherError> {
    rebuild_and_verify_acl(tools, installation, path, sid, "File")
}

fn rebuild_and_verify_acl(
    tools: &StartTools,
    installation: &Installation,
    path: &Path,
    sid: &str,
    kind: &str,
) -> Result<(), LauncherError> {
    platform::ensure_local_disk_path(path)?;
    let output = run_process(
        &tools.powershell,
        &[
            OsString::from("-NoLogo"),
            OsString::from("-NoProfile"),
            OsString::from("-NonInteractive"),
            OsString::from("-ExecutionPolicy"),
            OsString::from("Bypass"),
            OsString::from("-File"),
            installation.acl_script.as_os_str().to_os_string(),
            OsString::from("-TargetPath"),
            path.as_os_str().to_os_string(),
            OsString::from("-UserSid"),
            OsString::from(sid),
            OsString::from("-Kind"),
            OsString::from(kind),
        ],
        &[],
        &installation.install_dir,
        PROCESS_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(LauncherError::new(
            "SECRET_ACL_FAILED",
            "无法重建并验证受控 DACL；仅当前用户与 SYSTEM 被允许，已安全阻断。",
        ));
    }
    Ok(())
}

fn start(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<bool, LauncherError> {
    let inventory = inspect_compose_project_inventory(tools, installation, image_lock)?;
    let listeners = host_port_listeners(start_tools, installation)?;
    if listeners.iter().any(|address| address != "127.0.0.1") {
        return Err(LauncherError::new(
            "PUBLIC_LISTENER_REJECTED",
            "检测到 0.0.0.0、::、::1 或其他非 127.0.0.1 的 17860 监听；在未尝试启动前不会停止任何容器。",
        ));
    }
    if !listeners.is_empty() && !inventory.service_is_running("web") {
        return Err(LauncherError::new(
            "LOOPBACK_PORT_IN_USE",
            "127.0.0.1:17860 已被非本产品进程占用；Launcher 不会换端口或终止未知进程。",
        ));
    }

    let up = match compose_owned(
        tools,
        installation,
        image_lock,
        &[],
        false,
        &COMPOSE_UP_WITHOUT_PULL,
        COMPOSE_TIMEOUT,
    ) {
        Ok(output) => output,
        Err(error) => {
            return Err(clean_up_unhealthy_start(
                tools,
                installation,
                image_lock,
                error,
            ));
        }
    };
    if !up.status.success() {
        return Err(clean_up_unhealthy_start(
            tools,
            installation,
            image_lock,
            LauncherError::new(
                "COMPOSE_START_FAILED",
                "Docker Compose 启动失败。请检查 Docker Desktop 和签名发布镜像。",
            ),
        ));
    }
    let start_safety_checks = (|| -> Result<(), LauncherError> {
        let volume_contract = active_runtime_volume_contract(installation)?;
        validate_active_runtime_volume_contract(tools, installation, &volume_contract)?;
        validate_actual_compose_ports(tools, start_tools, installation, image_lock)?;
        verify_shared_network_namespace(tools, installation, image_lock)?;
        wait_for_http(LIVE_PATH, LIVE_TIMEOUT, "API_LIVE_TIMEOUT")?;
        verify_container_secret_targets(tools, installation, image_lock)
    })();
    if let Err(error) = start_safety_checks {
        return Err(clean_up_unhealthy_start(
            tools,
            installation,
            image_lock,
            error,
        ));
    }

    let resume = match lifecycle(tools, installation, image_lock, "resume") {
        Ok(value) => value,
        Err(error) => {
            return Err(clean_up_unhealthy_start(
                tools,
                installation,
                image_lock,
                error,
            ));
        }
    };
    if !resume.safe_to_stop {
        return Err(LauncherError::new(
            "RECOVERY_RECONCILIATION_REQUIRED",
            format!(
                "恢复对账尚未完成（{} 个执行，{} 个恢复探针）；系统保持 draining，未开放新执行。",
                resume.active_execution_count, resume.active_probe_count
            ),
        ));
    }
    if let Err(error) = wait_for_http(READY_PATH, READY_TIMEOUT, "SERVICE_NOT_READY") {
        return Err(clean_up_unhealthy_start(
            tools,
            installation,
            image_lock,
            error,
        ));
    }
    if !ensure_bootstrap_admin(tools, installation, image_lock)? {
        return Ok(false);
    }
    platform::open_browser(UI_URL)?;
    Ok(true)
}

fn clean_up_unhealthy_start(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    primary: LauncherError,
) -> LauncherError {
    let cleanup =
        inspect_compose_project_inventory(tools, installation, image_lock).and_then(|inventory| {
            if inventory.is_empty() {
                return Ok(());
            }
            compose_owned(
                tools,
                installation,
                image_lock,
                &[],
                false,
                &["down", "--timeout", "30"],
                COMPOSE_TIMEOUT,
            )
            .and_then(|output| {
                if output.status.success() {
                    Ok(())
                } else {
                    Err(LauncherError::new(
                        "COMPOSE_START_CLEANUP_FAILED",
                        "启动后自动停止不健康的 Compose 服务失败；named volumes 未被删除。",
                    ))
                }
            })
        });
    merge_unhealthy_start_cleanup_result(primary, cleanup)
}

fn merge_unhealthy_start_cleanup_result(
    primary: LauncherError,
    cleanup: Result<(), LauncherError>,
) -> LauncherError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup_error) if cleanup_error.code() == "COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED" => {
            LauncherError::new(
                "COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED",
                format!(
                    "启动后的安全核验失败（{}），且重新核验 Compose 容器归属失败；Launcher 未执行自动清理。",
                    primary.code(),
                ),
            )
        }
        Err(cleanup_error) => LauncherError::new(
            "STARTUP_CLEANUP_FAILED",
            format!(
                "启动后的安全核验失败（{}），且自动停止不健康的 Compose 服务失败（{}）。请停止使用本机并人工处置；named volumes 未被删除。",
                primary.code(),
                cleanup_error.code(),
            ),
        ),
    }
}

fn verify_container_secret_targets(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<(), LauncherError> {
    let api_output = compose_owned(
        tools,
        installation,
        image_lock,
        &["api"],
        true,
        &[
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            VERIFY_CONTAINER_SECRETS_SCRIPT,
        ],
        PROCESS_TIMEOUT,
    )?;
    let worker_output = compose_owned(
        tools,
        installation,
        image_lock,
        &["worker"],
        true,
        &[
            "exec",
            "-T",
            "worker",
            "python",
            "-c",
            VERIFY_WORKER_SECRETS_SCRIPT,
        ],
        PROCESS_TIMEOUT,
    )?;
    let guard_output = compose_owned(
        tools,
        installation,
        image_lock,
        &["egress-guard"],
        true,
        &[
            "exec",
            "-T",
            "egress-guard",
            "python3",
            "-c",
            VERIFY_EGRESS_GUARD_SECRET_SCRIPT,
        ],
        PROCESS_TIMEOUT,
    )?;
    if !api_output.status.success()
        || !api_output.stdout.is_empty()
        || !worker_output.status.success()
        || !worker_output.stdout.is_empty()
        || !guard_output.status.success()
        || !guard_output.stdout.is_empty()
    {
        return Err(LauncherError::new(
            "CONTAINER_SECRET_TARGET_INVALID",
            "API/Worker/egress-guard 容器内 secret 的实际 target、文件类型或长度不符合固定契约。",
        ));
    }
    Ok(())
}

fn verify_container_secret_targets_for_runtime(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    let api_output = compose_owned_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
        &["api"],
        true,
        &[
            "exec",
            "-T",
            "api",
            "python",
            "-c",
            VERIFY_CONTAINER_SECRETS_SCRIPT,
        ],
        PROCESS_TIMEOUT,
    )?;
    let worker_output = compose_owned_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
        &["worker"],
        true,
        &[
            "exec",
            "-T",
            "worker",
            "python",
            "-c",
            VERIFY_WORKER_SECRETS_SCRIPT,
        ],
        PROCESS_TIMEOUT,
    )?;
    let guard_output = compose_owned_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
        &["egress-guard"],
        true,
        &[
            "exec",
            "-T",
            "egress-guard",
            "python3",
            "-c",
            VERIFY_EGRESS_GUARD_SECRET_SCRIPT,
        ],
        PROCESS_TIMEOUT,
    )?;
    if !api_output.status.success()
        || !api_output.stdout.is_empty()
        || !worker_output.status.success()
        || !worker_output.stdout.is_empty()
        || !guard_output.status.success()
        || !guard_output.stdout.is_empty()
    {
        return Err(LauncherError::new(
            "CONTAINER_SECRET_TARGET_INVALID",
            "API/Worker/egress-guard 容器内 secret 的实际 target、文件类型或长度不符合固定契约。",
        ));
    }
    Ok(())
}

fn verify_shared_network_namespace(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<(), LauncherError> {
    let mut namespaces = BTreeSet::new();
    for (service, interpreter) in [
        ("egress-guard", "python3"),
        ("api", "python"),
        ("worker", "python"),
    ] {
        let output = compose_owned(
            tools,
            installation,
            image_lock,
            &[service],
            true,
            &[
                "exec",
                "-T",
                service,
                interpreter,
                "-c",
                NETWORK_NAMESPACE_SCRIPT,
            ],
            PROCESS_TIMEOUT,
        )?;
        let namespace = std::str::from_utf8(&output.stdout).ok();
        if !output.status.success()
            || !output.stderr.is_empty()
            || namespace.is_none_or(|value| !is_network_namespace_id(value))
        {
            return Err(LauncherError::new(
                "EGRESS_NETWORK_NAMESPACE_UNVERIFIED",
                "无法核验 API、Worker 与 egress-guard 的实际 Linux 网络命名空间。",
            ));
        }
        namespaces.insert(namespace.unwrap().to_owned());
    }
    if namespaces.len() != 1 {
        return Err(LauncherError::new(
            "EGRESS_NETWORK_NAMESPACE_MISMATCH",
            "API、Worker 与 egress-guard 未共享同一个实际 Linux 网络命名空间。",
        ));
    }
    Ok(())
}

fn verify_shared_network_namespace_for_runtime(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    let mut namespaces = BTreeSet::new();
    for (service, interpreter) in [
        ("egress-guard", "python3"),
        ("api", "python"),
        ("worker", "python"),
    ] {
        let output = compose_owned_for_runtime(
            tools,
            installation,
            image_lock,
            active_runtime,
            &[service],
            true,
            &[
                "exec",
                "-T",
                service,
                interpreter,
                "-c",
                NETWORK_NAMESPACE_SCRIPT,
            ],
            PROCESS_TIMEOUT,
        )?;
        let namespace = std::str::from_utf8(&output.stdout).ok();
        if !output.status.success()
            || !output.stderr.is_empty()
            || namespace.is_none_or(|value| !is_network_namespace_id(value))
        {
            return Err(LauncherError::new(
                "EGRESS_NETWORK_NAMESPACE_UNVERIFIED",
                "无法核验 API、Worker 与 egress-guard 的实际 Linux 网络命名空间。",
            ));
        }
        namespaces.insert(namespace.unwrap().to_owned());
    }
    if namespaces.len() != 1 {
        return Err(LauncherError::new(
            "EGRESS_NETWORK_NAMESPACE_MISMATCH",
            "API、Worker 与 egress-guard 未共享同一个实际 Linux 网络命名空间。",
        ));
    }
    Ok(())
}

fn is_network_namespace_id(value: &str) -> bool {
    value
        .strip_prefix("net:[")
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|identifier| {
            !identifier.is_empty() && identifier.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn ensure_bootstrap_admin(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<bool, LauncherError> {
    if bootstrap_status(tools, installation, image_lock)? == BootstrapState::Complete {
        return Ok(true);
    }

    let Some(mut input) = platform::prompt_bootstrap_admin()? else {
        return Ok(false);
    };
    validate_bootstrap_identity(&mut input)?;
    let password_stdin = encode_bootstrap_password(&mut input)?;
    let arguments = vec![
        OsString::from("exec"),
        OsString::from("-T"),
        OsString::from("api"),
        OsString::from("datax-studio-bootstrap-admin"),
        OsString::from("--email"),
        OsString::from(&input.email),
        OsString::from("--display-name"),
        OsString::from(&input.display_name),
        OsString::from("--organization-name"),
        OsString::from(PRODUCT_NAME),
        OsString::from("--json"),
    ];
    let inventory = inspect_compose_project_inventory(tools, installation, image_lock)?;
    require_authenticated_compose_services(&inventory, &["api"], true)?;
    let mut output = compose_with_secret_stdin(
        tools,
        installation,
        &arguments,
        COMPOSE_TIMEOUT,
        password_stdin,
    )?;
    output.stderr.zeroize();
    let parsed: BootstrapCreateResult = serde_json::from_slice(&output.stdout).map_err(|_| {
        LauncherError::new(
            "BOOTSTRAP_RESPONSE_INVALID",
            "一次性管理员 helper 未返回有效 JSON；浏览器未打开。",
        )
    })?;
    match interpret_bootstrap_create_response(output.status.code(), &parsed)? {
        BootstrapCreateState::Created => {
            if bootstrap_status(tools, installation, image_lock)? != BootstrapState::Complete {
                return Err(LauncherError::new(
                    "BOOTSTRAP_POSTCHECK_FAILED",
                    "管理员 helper 报告创建成功，但只读复核未确认完成；浏览器未打开。",
                ));
            }
            platform::show_info(
                PRODUCT_NAME,
                "首次管理员已创建。首次登录后必须立即修改临时密码。",
            );
            Ok(true)
        }
        BootstrapCreateState::AlreadyCompleted => Err(LauncherError::new(
            "BOOTSTRAP_ALREADY_COMPLETED",
            "提交期间检测到已有管理员；未暴露任何现有账号信息。请重新启动 Launcher。",
        )),
        BootstrapCreateState::InputInvalid => Err(LauncherError::new(
            "BOOTSTRAP_INPUT_INVALID",
            "管理员信息未通过服务端校验；未创建账号，浏览器未打开。",
        )),
        BootstrapCreateState::InternalError => Err(LauncherError::new(
            "BOOTSTRAP_INTERNAL_ERROR",
            "一次性管理员 helper 执行失败；未创建账号，浏览器未打开。",
        )),
    }
}

fn bootstrap_status(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<BootstrapState, LauncherError> {
    let mut output = compose_owned(
        tools,
        installation,
        image_lock,
        &["api"],
        true,
        &[
            "exec",
            "-T",
            "api",
            "datax-studio-bootstrap-admin",
            "--status",
            "--json",
        ],
        PROCESS_TIMEOUT,
    )?;
    output.stderr.zeroize();
    let parsed: BootstrapStatus = serde_json::from_slice(&output.stdout).map_err(|_| {
        LauncherError::new(
            "BOOTSTRAP_STATUS_INVALID",
            "无法解析一次性管理员只读状态；已安全阻断首次引导。",
        )
    })?;
    interpret_bootstrap_status_response(output.status.code(), &parsed)
}

fn interpret_bootstrap_status_response(
    exit_code: Option<i32>,
    parsed: &BootstrapStatus,
) -> Result<BootstrapState, LauncherError> {
    match (exit_code, parsed.required, parsed.code.as_str()) {
        (Some(0), Some(true), "BOOTSTRAP_REQUIRED") => Ok(BootstrapState::Required),
        (Some(3), Some(false), "BOOTSTRAP_ALREADY_COMPLETED") => Ok(BootstrapState::Complete),
        (Some(4), None, "BOOTSTRAP_CHECK_FAILED") => Err(LauncherError::new(
            "BOOTSTRAP_CHECK_FAILED",
            "一次性管理员状态检查失败；Launcher 不会猜测数据库是否为空。",
        )),
        (Some(4), None, "BOOTSTRAP_INPUT_INVALID") => Err(LauncherError::new(
            "BOOTSTRAP_STATUS_INVALID",
            "一次性管理员状态 helper 拒绝了固定参数；已安全阻断。",
        )),
        _ => Err(LauncherError::new(
            "BOOTSTRAP_STATUS_INVALID",
            format!(
                "一次性管理员状态 helper 返回矛盾状态（exit={:?}）；已安全阻断。",
                exit_code
            ),
        )),
    }
}

fn interpret_bootstrap_create_response(
    exit_code: Option<i32>,
    parsed: &BootstrapCreateResult,
) -> Result<BootstrapCreateState, LauncherError> {
    match (exit_code, parsed.created, parsed.code.as_str()) {
        (Some(0), true, "BOOTSTRAP_ADMIN_CREATED") => Ok(BootstrapCreateState::Created),
        (Some(3), false, "BOOTSTRAP_ALREADY_COMPLETED") => {
            Ok(BootstrapCreateState::AlreadyCompleted)
        }
        (Some(4), false, "BOOTSTRAP_INPUT_INVALID") => Ok(BootstrapCreateState::InputInvalid),
        (Some(4), false, "BOOTSTRAP_INTERNAL_ERROR") => Ok(BootstrapCreateState::InternalError),
        _ => Err(LauncherError::new(
            "BOOTSTRAP_RESPONSE_INVALID",
            format!("一次性管理员 helper 返回矛盾状态（exit={exit_code:?}）；浏览器未打开。"),
        )),
    }
}

fn validate_bootstrap_identity(input: &mut BootstrapInput) -> Result<(), LauncherError> {
    let email = input.email.trim();
    let email_length = email.chars().count();
    if email_length == 0
        || email_length > 254
        || email.matches('@').count() != 1
        || email.starts_with('@')
        || email.ends_with('@')
        || email
            .chars()
            .any(|character| character.is_whitespace() || character == '\0')
    {
        return Err(LauncherError::new(
            "BOOTSTRAP_EMAIL_INVALID",
            "登录邮箱格式无效。",
        ));
    }
    let display_name = input.display_name.trim();
    if !(1..=128).contains(&display_name.chars().count())
        || display_name
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return Err(LauncherError::new(
            "BOOTSTRAP_DISPLAY_NAME_INVALID",
            "显示名必须为 1 至 128 个字符，且不能包含换行或 NUL。",
        ));
    }
    input.email = email.to_owned();
    input.display_name = display_name.to_owned();
    Ok(())
}

fn encode_bootstrap_password(
    input: &mut BootstrapInput,
) -> Result<Zeroizing<Vec<u8>>, LauncherError> {
    let decoded = String::from_utf16(&input.password_utf16);
    input.password_utf16.zeroize();
    let password = Zeroizing::new(decoded.map_err(|_| {
        LauncherError::new("BOOTSTRAP_PASSWORD_INVALID", "临时密码包含无效 Unicode。")
    })?);
    let length = password.chars().count();
    if !(12..=256).contains(&length)
        || password
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return Err(LauncherError::new(
            "BOOTSTRAP_PASSWORD_INVALID",
            "临时密码必须为 12 至 256 个字符，且不能包含换行或 NUL。",
        ));
    }
    let mut stdin = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    stdin.extend_from_slice(password.as_bytes());
    stdin.push(b'\n');
    Ok(stdin)
}

fn stage_system_restore(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
    request: RestoreRequestPaths<'_>,
) -> Result<RunOutcome, LauncherError> {
    ensure_clean_restore_target(tools, installation)?;
    let prepared = prepare_restore_staging(start_tools, installation, request)?;
    let mounts = vec![
        docker_bind_mount(&prepared.data_input, "/restore/input/data.dxdata")?,
        docker_bind_mount(&prepared.secrets_input, "/restore/input/secrets.dxkeys")?,
        docker_writable_bind_mount(&prepared.staging_root, "/restore/staging")?,
        docker_writable_bind_mount(&prepared.journal_directory, "/restore/journal")?,
    ];
    let helper = restore_stage_helper_container(&prepared);
    let mut arguments = restore_stage_container_arguments(&image_lock.worker, &mounts, &helper);
    arguments.extend([
        OsString::from("stage-restore-pair"),
        OsString::from("--data-input"),
        OsString::from("/restore/input/data.dxdata"),
        OsString::from("--secrets-input"),
        OsString::from("/restore/input/secrets.dxkeys"),
        OsString::from("--staging-root"),
        OsString::from("/restore/staging"),
        OsString::from("--journal"),
        OsString::from("/restore/journal/restore.json"),
        OsString::from("--expected-product-version"),
        OsString::from(env!("CARGO_PKG_VERSION")),
        OsString::from("--expected-migration-revision"),
        OsString::from(SUPPORTED_MIGRATION_REVISION),
        OsString::from("--expected-release-manifest-sha256"),
        OsString::from(RELEASE_MANIFEST_BOUND_SHA256.ok_or_else(|| {
            LauncherError::new(
                "RELEASE_BINDING_MISSING",
                "Launcher 构建未绑定发布清单，已拒绝恢复 staging。",
            )
        })?),
    ]);
    let result = run_helper_with_cleanup(
        tools,
        installation,
        &helper,
        &arguments,
        restore_password_pair_stdin(&prepared.data_key, &prepared.secrets_key),
        |mut output| {
            output.stderr.zeroize();
            parse_restore_stage_output(&output)
        },
    )?;

    platform::ensure_regular_file(&prepared.journal_path)?;
    let sid = current_user_sid(start_tools, installation)?;
    restrict_file_acl(start_tools, installation, &prepared.journal_path, &sid)?;
    restrict_directory_acl(start_tools, installation, &prepared.staging_root, &sid)?;
    Err(LauncherError::new(
        "RESTORE_STAGED_COMMIT_BLOCKED",
        format!(
            "恢复包已认证并写入受控 staging（journal={}，installation={}）；新空 PostgreSQL volume、pg_restore、证据重算和 RESTORE 代际提交尚未执行。",
            result.journal_id, result.installation_id
        ),
    ))
}

fn ensure_clean_restore_target(
    tools: &Tools,
    installation: &Installation,
) -> Result<(), LauncherError> {
    let generations = installation.app_data_root.join("generations");
    for path in [
        &installation.initialization_state,
        &installation.installation_id,
        &installation.runtime_generation,
        &installation.secret_dir,
        &generations,
    ] {
        ensure_restore_identity_path_absent(path)?;
    }

    if installation.app_data_root.exists() {
        platform::ensure_directory(&installation.app_data_root)?;
        ensure_directory_entries_allowed(
            &installation.app_data_root,
            &["system-restore", DOCKER_CLI_CONFIG_DIRECTORY_NAME],
        )?;
    }
    let restore_root = installation.app_data_root.join("system-restore");
    if restore_root.exists() {
        platform::ensure_directory(&restore_root)?;
        ensure_directory_entries_allowed(&restore_root, &["staging", "journal"])?;
    }

    let containers = docker(
        tools,
        installation,
        &["ps", "--all", "--format", "{{.Names}}"],
        PROCESS_TIMEOUT,
    )?;
    if !containers.status.success()
        || normalize_text(&containers.stdout).lines().any(|name| {
            let name = name.trim();
            name.starts_with("datax-enterprise-studio-") || name.starts_with("des-restore-")
        })
    {
        return Err(LauncherError::new(
            "RESTORE_PRODUCT_CONTAINER_PRESENT",
            "检测到产品或恢复容器；干净目标恢复不会停止、复用或覆盖它。",
        ));
    }

    let volumes = docker(
        tools,
        installation,
        &["volume", "ls", "--quiet"],
        PROCESS_TIMEOUT,
    )?;
    if !volumes.status.success()
        || normalize_text(&volumes.stdout)
            .lines()
            .any(|name| is_product_volume_name(name.trim()))
    {
        return Err(LauncherError::new(
            "RESTORE_PRODUCT_VOLUME_PRESENT",
            "检测到产品 named volume；V1 恢复不会覆盖、重命名或删除已有卷。",
        ));
    }
    let labeled_volumes = docker(
        tools,
        installation,
        &[
            "volume",
            "ls",
            "--quiet",
            "--filter",
            "label=com.xiaoli.datax.volume-role",
        ],
        PROCESS_TIMEOUT,
    )?;
    if !labeled_volumes.status.success()
        || normalize_text(&labeled_volumes.stdout)
            .lines()
            .any(|name| !name.trim().is_empty())
    {
        return Err(LauncherError::new(
            "RESTORE_PRODUCT_VOLUME_PRESENT",
            "检测到带产品角色标签的 named volume；V1 恢复不会复用或删除它。",
        ));
    }
    Ok(())
}

fn ensure_no_restore_in_progress(app_data_root: &Path) -> Result<(), LauncherError> {
    let restore_root = app_data_root.join("system-restore");
    match fs::symlink_metadata(&restore_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LauncherError::new(
            "RESTORE_STATE_CHECK_FAILED",
            "无法证明本机不存在未完成的系统恢复；普通启动和备份已安全阻断。",
        )),
        Ok(_) => Err(LauncherError::new(
            "RESTORE_IN_PROGRESS",
            "检测到受控 system-restore 状态。普通启动和备份不会把部分恢复初始化为空白安装，也不会生成替代 secret、installation-id 或数据卷；请使用同一包对和恢复秘密继续恢复，或走 journal 授权的清理流程。",
        )),
    }
}

fn ensure_restore_identity_path_absent(path: &Path) -> Result<(), LauncherError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(LauncherError::new(
            "RESTORE_CLEAN_TARGET_REQUIRED",
            "恢复只允许没有初始化日志、安装身份、活动代际或运行 secret 的干净目标。",
        )),
        Err(_) => Err(LauncherError::new(
            "RESTORE_TARGET_CHECK_FAILED",
            "无法证明恢复目标不存在旧身份对象。",
        )),
    }
}

fn ensure_directory_entries_allowed(path: &Path, allowed: &[&str]) -> Result<(), LauncherError> {
    let entries = fs::read_dir(path).map_err(|_| {
        LauncherError::new("RESTORE_TARGET_CHECK_FAILED", "无法枚举干净恢复目标目录。")
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            LauncherError::new(
                "RESTORE_TARGET_CHECK_FAILED",
                "无法读取干净恢复目标目录项。",
            )
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(LauncherError::new(
                "RESTORE_CLEAN_TARGET_REQUIRED",
                "恢复目标包含无法识别的目录项。",
            ));
        };
        if !allowed.contains(&name.as_str()) {
            return Err(LauncherError::new(
                "RESTORE_CLEAN_TARGET_REQUIRED",
                "恢复目标包含不属于当前受认证 journal 的对象。",
            ));
        }
    }
    Ok(())
}

fn is_product_volume_name(name: &str) -> bool {
    RUNTIME_VOLUMES.iter().any(|(fixed, _)| name == *fixed)
        || ["des-postgres-", "des-log-", "des-workspace-"]
            .iter()
            .any(|prefix| {
                name.strip_prefix(prefix)
                    .is_some_and(|suffix| is_lower_hex_string(suffix, 32))
            })
}

fn is_lower_hex_string(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn prepare_restore_staging(
    start_tools: &StartTools,
    installation: &Installation,
    request: RestoreRequestPaths<'_>,
) -> Result<PreparedRestore, LauncherError> {
    let data_input = validate_restore_package_file(request.data_input, ".dxdata")?;
    let secrets_input = validate_restore_package_file(request.secrets_input, ".dxkeys")?;
    let data_key_path = validate_backup_key_file(request.data_key)?;
    let secrets_key_path = validate_backup_key_file(request.secrets_key)?;
    let install_dir = fs::canonicalize(&installation.install_dir)
        .map_err(|_| LauncherError::new("RESTORE_PATH_INVALID", "无法规范化安装目录。"))?;
    let paths = [
        &data_input,
        &secrets_input,
        &data_key_path,
        &secrets_key_path,
    ];
    for (index, left) in paths.iter().enumerate() {
        if left.starts_with(&install_dir)
            || paths
                .iter()
                .skip(index + 1)
                .any(|right| paths_overlap(left, right))
        {
            return Err(LauncherError::new(
                "RESTORE_PATH_OVERLAP_REJECTED",
                "恢复包、两把 key 与安装资源路径必须彼此分离。",
            ));
        }
    }

    create_controlled_directory(&installation.app_data_root)?;
    platform::ensure_directory(&installation.app_data_root)?;
    let sid = current_user_sid(start_tools, installation)?;
    restrict_directory_acl(start_tools, installation, &installation.app_data_root, &sid)?;
    let restore_root = installation.app_data_root.join("system-restore");
    let staging_root = restore_root.join("staging");
    let journal_directory = restore_root.join("journal");
    for directory in [&restore_root, &staging_root, &journal_directory] {
        create_controlled_directory(directory)?;
        platform::ensure_directory(directory)?;
        restrict_directory_acl(start_tools, installation, directory, &sid)?;
    }
    ensure_directory_entries_allowed(&restore_root, &["staging", "journal"])?;
    ensure_directory_entries_allowed(&journal_directory, &["restore.json"])?;
    let journal_path = journal_directory.join("restore.json");
    if journal_path.exists() {
        platform::ensure_regular_file(&journal_path)?;
        restrict_file_acl(start_tools, installation, &journal_path, &sid)?;
    } else {
        ensure_directory_entries_allowed(&staging_root, &[])?;
    }

    restrict_file_acl(start_tools, installation, request.data_key, &sid)?;
    restrict_file_acl(start_tools, installation, request.secrets_key, &sid)?;
    let data_key = read_backup_key(&data_key_path)?;
    let secrets_key = read_backup_key(&secrets_key_path)?;
    if constant_time_bytes_equal(&data_key, &secrets_key) {
        return Err(LauncherError::new(
            "RESTORE_KEY_REUSE_REJECTED",
            "DATA 与 SECRETS 恢复 key 必须不同。",
        ));
    }
    Ok(PreparedRestore {
        data_input,
        secrets_input,
        data_key,
        secrets_key,
        staging_root: fs::canonicalize(staging_root).map_err(|_| {
            LauncherError::new("RESTORE_PATH_INVALID", "无法规范化恢复 staging 目录。")
        })?,
        journal_directory: fs::canonicalize(journal_directory).map_err(|_| {
            LauncherError::new("RESTORE_PATH_INVALID", "无法规范化恢复 journal 目录。")
        })?,
        journal_path,
        current_user_sid: sid,
    })
}

fn validate_restore_package_file(path: &Path, suffix: &str) -> Result<PathBuf, LauncherError> {
    platform::ensure_local_disk_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| LauncherError::new("RESTORE_PACKAGE_INVALID", "恢复包路径缺少父目录。"))?;
    platform::ensure_tree_no_reparse(parent)?;
    platform::ensure_regular_file(path)?;
    let valid_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(suffix) && name.len() > suffix.len());
    if !valid_name {
        return Err(LauncherError::new(
            "RESTORE_PACKAGE_INVALID",
            "恢复包扩展名与 DATA/SECRETS 角色不匹配。",
        ));
    }
    fs::canonicalize(path)
        .map_err(|_| LauncherError::new("RESTORE_PACKAGE_INVALID", "无法规范化恢复包路径。"))
}

fn restore_password_pair_stdin(data_key: &[u8], secrets_key: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut stdin = Zeroizing::new(Vec::with_capacity(data_key.len() + secrets_key.len() + 2));
    stdin.extend_from_slice(data_key);
    stdin.push(b'\n');
    stdin.extend_from_slice(secrets_key);
    stdin.push(b'\n');
    stdin
}

fn parse_restore_stage_output(output: &ProcessOutput) -> Result<RestoreStageResult, LauncherError> {
    if output.status.code() == Some(3) {
        let result: RestoreStageResult = serde_json::from_slice(&output.stdout).map_err(|_| {
            LauncherError::new(
                "RESTORE_HELPER_RESPONSE_INVALID",
                "恢复 staging helper 返回了无效响应。",
            )
        })?;
        if restore_stage_result_valid(&result) {
            return Ok(result);
        }
        return Err(LauncherError::new(
            "RESTORE_HELPER_RESPONSE_INVALID",
            "恢复 staging helper 返回了矛盾状态。",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        LauncherError::new(
            "RESTORE_STAGE_HELPER_FAILED",
            "恢复包认证或 staging 失败，helper 未返回受支持的错误结构。",
        )
    })?;
    let object = value.as_object();
    let code = object
        .and_then(|value| value.get("code"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| is_stable_error_code(value));
    Err(LauncherError::new(
        code.unwrap_or("RESTORE_STAGE_HELPER_FAILED"),
        "恢复包认证或 staging 失败；没有创建或修改活动运行代际。",
    ))
}

fn restore_stage_result_valid(result: &RestoreStageResult) -> bool {
    result.schema_version == "1.0"
        && result.code == "RESTORE_STAGED_COMMIT_BLOCKED"
        && result.state == "STAGED_COMMIT_BLOCKED"
        && result.next_required_gate == "PG_RESTORE_NEW_EMPTY_VOLUME_AND_ATOMIC_COMMIT"
        && is_lower_hex_string(&result.journal_id, 32)
        && is_lower_hex_string(&result.data_backup_id, 32)
        && is_lower_hex_string(&result.secrets_backup_id, 32)
        && is_lower_hex_string(&result.installation_id, 64)
}

fn is_stable_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn create_system_backup(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
    request: BackupRequestPaths<'_>,
) -> Result<(PathBuf, PathBuf), LauncherError> {
    let prepared = prepare_system_backup(
        tools,
        start_tools,
        installation,
        request.data_output,
        request.secrets_output,
        request.data_key,
        request.secrets_key,
    )?;
    require_active_runtime_snapshot_unchanged(installation, &prepared.active_runtime)?;
    verify_compose_config_for_runtime(tools, installation, image_lock, &prepared.active_runtime)?;
    let inventory = inspect_compose_project_inventory_for_runtime(
        tools,
        installation,
        image_lock,
        &prepared.active_runtime,
    )?;
    require_active_runtime_snapshot_unchanged(installation, &prepared.active_runtime)?;
    if !inventory.is_complete() || !inventory.service_is_running("web") {
        return Err(LauncherError::new(
            "BACKUP_RUNNING_SERVICE_REQUIRED",
            "系统备份必须从已正常运行的本机服务发起，以便先进入 draining 并证明没有活动任务。",
        ));
    }
    let staging = prepare_backup_staging(start_tools, installation, &prepared.current_user_sid)?;

    let preflight = match lifecycle_for_runtime(
        tools,
        installation,
        image_lock,
        &prepared.active_runtime,
        "preflight-stop",
    ) {
        Ok(value) => value,
        Err(error) => {
            cleanup_staging_and_resume_after_backup_abort(
                tools,
                start_tools,
                installation,
                image_lock,
                &prepared,
                &staging,
                error.code(),
            )?;
            return Err(error);
        }
    };
    if !preflight.safe_to_stop {
        cleanup_staging_and_resume_after_backup_abort(
            tools,
            start_tools,
            installation,
            image_lock,
            &prepared,
            &staging,
            "ACTIVE_ATTEMPTS_PRESENT",
        )?;
        return Err(LauncherError::new(
            "ACTIVE_ATTEMPTS_PRESENT",
            format!(
                "系统备份被拒绝：仍有 {} 个活动执行和 {} 个活动恢复探针。",
                preflight.active_execution_count, preflight.active_probe_count
            ),
        ));
    }

    let operation = perform_system_backup(
        tools,
        start_tools,
        installation,
        image_lock,
        &prepared,
        &staging,
    );
    let cleanup = cleanup_backup_staging(&staging);

    if let Err(cleanup_error) = cleanup {
        return match operation {
            Ok((data_package, secrets_package)) => Err(LauncherError::new(
                "BACKUP_STAGING_CLEANUP_FAILED",
                format!(
                    "加密备份包已生成（DATA={}，SECRETS={}），但明文 pg_dump staging 清理失败：{}。Launcher 不会执行 resume；请先核验当前服务状态并人工处置。",
                    data_package.display(),
                    secrets_package.display(),
                    cleanup_error.code(),
                ),
            )),
            Err(operation_error) => Err(LauncherError::new(
                "BACKUP_STAGING_CLEANUP_FAILED",
                format!(
                    "系统备份失败（{}），且明文 pg_dump staging 清理失败（{}）。Launcher 不会执行 resume；请先核验当前服务状态并人工处置。",
                    operation_error.code(),
                    cleanup_error.code(),
                ),
            )),
        };
    }

    let resume = require_active_runtime_snapshot_unchanged(installation, &prepared.active_runtime)
        .and_then(|_| {
            resume_services_after_system_backup(
                tools,
                start_tools,
                installation,
                image_lock,
                &prepared.active_runtime,
            )
        });

    match operation {
        Ok((data_package, secrets_package)) => {
            if let Err(error) = resume {
                return Err(LauncherError::new(
                    "BACKUP_CREATED_RESUME_FAILED",
                    format!(
                        "加密备份包已生成（DATA={}，SECRETS={}），但本机服务恢复失败：{}。备份不等于恢复验收。",
                        data_package.display(),
                        secrets_package.display(),
                        error.code(),
                    ),
                ));
            }
            Ok((data_package, secrets_package))
        }
        Err(operation_error) => {
            if let Err(resume_error) = resume {
                return Err(LauncherError::new(
                    "BACKUP_FAILED_RESUME_FAILED",
                    format!(
                        "系统备份失败（{}），随后本机服务恢复也失败（{}）。",
                        operation_error.code(),
                        resume_error.code(),
                    ),
                ));
            }
            Err(operation_error)
        }
    }
}

fn cleanup_staging_and_resume_after_backup_abort(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
    prepared: &PreparedBackup,
    staging: &BackupStaging,
    primary_code: &str,
) -> Result<(), LauncherError> {
    if let Err(cleanup_error) = cleanup_backup_staging(staging) {
        return Err(LauncherError::new(
            "BACKUP_STAGING_CLEANUP_FAILED",
            format!(
                "系统备份预检被中止（{}），且 staging 清理失败（{}）。Launcher 不会执行 resume；请先核验当前服务状态并人工处置。",
                primary_code,
                cleanup_error.code(),
            ),
        ));
    }
    require_active_runtime_snapshot_unchanged(installation, &prepared.active_runtime)?;
    resume_services_after_system_backup(
        tools,
        start_tools,
        installation,
        image_lock,
        &prepared.active_runtime,
    )
    .map_err(|error| {
        LauncherError::new(
            "BACKUP_PREFLIGHT_RESUME_FAILED",
            format!(
                "系统备份预检被中止（{}），随后本机服务恢复失败（{}）。",
                primary_code,
                error.code(),
            ),
        )
    })
}

fn prepare_system_backup(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    data_output: &Path,
    secrets_output: &Path,
    data_key: &Path,
    secrets_key: &Path,
) -> Result<PreparedBackup, LauncherError> {
    if installation.initialization_state.exists() {
        return Err(LauncherError::new(
            "BACKUP_INITIALIZATION_INCOMPLETE",
            "首次初始化日志仍存在；系统身份尚未完整提交，已拒绝备份。",
        ));
    }
    let current_user_sid = current_user_sid(start_tools, installation)?;
    let active_runtime =
        load_verified_active_runtime_snapshot(start_tools, installation, &current_user_sid)?;
    let volume_contract = active_runtime.volume_contract();
    validate_active_runtime_volume_contract(tools, installation, &volume_contract)?;
    verify_active_runtime_secret_set(
        start_tools,
        installation,
        &current_user_sid,
        &active_runtime,
    )?;
    let installation_id = active_runtime.generation.installation_id.clone();

    let data_output =
        prepare_backup_output_directory(start_tools, installation, data_output, &current_user_sid)?;
    let secrets_output = prepare_backup_output_directory(
        start_tools,
        installation,
        secrets_output,
        &current_user_sid,
    )?;
    let data_key_path = validate_backup_key_file(data_key)?;
    let secrets_key_path = validate_backup_key_file(secrets_key)?;

    let canonical_secret_dir =
        fs::canonicalize(&active_runtime.secrets.directory).map_err(|_| {
            LauncherError::new("BACKUP_PATH_INVALID", "无法规范化 Launcher secret 目录。")
        })?;
    let canonical_install_dir = fs::canonicalize(&installation.install_dir)
        .map_err(|_| LauncherError::new("BACKUP_PATH_INVALID", "无法规范化安装目录。"))?;
    let canonical_app_data = fs::canonicalize(&installation.app_data_root)
        .map_err(|_| LauncherError::new("BACKUP_PATH_INVALID", "无法规范化应用数据目录。"))?;
    let staging_root = canonical_app_data.join("backup-staging");
    let unsafe_overlap = paths_overlap(&data_output, &secrets_output)
        || paths_overlap(&data_output, &data_key_path)
        || paths_overlap(&data_output, &secrets_key_path)
        || paths_overlap(&secrets_output, &data_key_path)
        || paths_overlap(&secrets_output, &secrets_key_path)
        || paths_overlap(&data_output, &canonical_app_data)
        || paths_overlap(&secrets_output, &canonical_app_data)
        || paths_overlap(&data_output, &canonical_secret_dir)
        || paths_overlap(&secrets_output, &canonical_secret_dir)
        || paths_overlap(&data_output, &canonical_install_dir)
        || paths_overlap(&secrets_output, &canonical_install_dir)
        || paths_overlap(&data_output, &staging_root)
        || paths_overlap(&secrets_output, &staging_root)
        || paths_overlap(&data_key_path, &canonical_app_data)
        || paths_overlap(&secrets_key_path, &canonical_app_data)
        || paths_overlap(&data_key_path, &canonical_secret_dir)
        || paths_overlap(&secrets_key_path, &canonical_secret_dir)
        || paths_overlap(&data_key_path, &canonical_install_dir)
        || paths_overlap(&secrets_key_path, &canonical_install_dir);
    if unsafe_overlap || data_key_path == secrets_key_path {
        return Err(LauncherError::new(
            "BACKUP_PATH_OVERLAP_REJECTED",
            "DATA、SECRETS、两把 key、安装资源、应用数据、运行 secret 与明文 staging 路径必须完全分离。",
        ));
    }

    restrict_file_acl(start_tools, installation, data_key, &current_user_sid)?;
    restrict_file_acl(start_tools, installation, secrets_key, &current_user_sid)?;
    let data_key = read_backup_key(&data_key_path)?;
    let secrets_key = read_backup_key(&secrets_key_path)?;
    if constant_time_bytes_equal(&data_key, &secrets_key) {
        return Err(LauncherError::new(
            "BACKUP_KEY_REUSE_REJECTED",
            "DATA 与 SECRETS 必须使用不同恢复 key。",
        ));
    }
    validate_backup_key_domain_separation(&active_runtime.secrets, &data_key, &secrets_key)?;
    Ok(PreparedBackup {
        data_output,
        secrets_output,
        data_key,
        secrets_key,
        active_runtime,
        installation_id,
        current_user_sid,
    })
}

fn prepare_backup_output_directory(
    start_tools: &StartTools,
    installation: &Installation,
    path: &Path,
    sid: &str,
) -> Result<PathBuf, LauncherError> {
    platform::ensure_local_disk_path(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(LauncherError::new(
                "BACKUP_OUTPUT_ALREADY_EXISTS",
                "备份输出目录必须是尚不存在的新目录；Launcher 不会改写已有目录的 ACL。",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                LauncherError::new("BACKUP_PATH_INVALID", "备份输出目录缺少父目录。")
            })?;
            platform::ensure_tree_no_reparse(parent)?;
            fs::create_dir(path).map_err(|_| {
                LauncherError::new("BACKUP_OUTPUT_CREATE_FAILED", "无法创建备份输出目录。")
            })?;
            platform::ensure_tree_no_reparse(path)?;
        }
        Err(_) => {
            return Err(LauncherError::new(
                "BACKUP_PATH_INVALID",
                "无法检查备份输出目录。",
            ));
        }
    }
    restrict_directory_acl(start_tools, installation, path, sid)?;
    fs::canonicalize(path)
        .map_err(|_| LauncherError::new("BACKUP_PATH_INVALID", "无法规范化备份输出目录。"))
}

fn validate_backup_key_file(path: &Path) -> Result<PathBuf, LauncherError> {
    platform::ensure_local_disk_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| LauncherError::new("BACKUP_KEY_INVALID", "恢复 key 文件缺少父目录。"))?;
    platform::ensure_tree_no_reparse(parent)?;
    platform::ensure_regular_file(path)?;
    let mut value = Zeroizing::new(read_bounded_file(path, 64, "BACKUP_KEY_INVALID")?);
    if !is_secret_bytes(&value) {
        value.zeroize();
        return Err(LauncherError::new(
            "BACKUP_KEY_INVALID",
            "恢复 key 必须恰好是 64 bytes 小写十六进制且无换行。",
        ));
    }
    fs::canonicalize(path)
        .map_err(|_| LauncherError::new("BACKUP_KEY_INVALID", "无法规范化恢复 key 文件。"))
}

fn read_backup_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, LauncherError> {
    let mut value = Zeroizing::new(read_bounded_file(path, 64, "BACKUP_KEY_INVALID")?);
    if !is_secret_bytes(&value) {
        value.zeroize();
        return Err(LauncherError::new(
            "BACKUP_KEY_INVALID",
            "恢复 key 必须恰好是 64 bytes 小写十六进制且无换行。",
        ));
    }
    Ok(value)
}

fn validate_backup_key_domain_separation(
    secrets: &RuntimeSecretPaths,
    data_key: &[u8],
    secrets_key: &[u8],
) -> Result<(), LauncherError> {
    for path in secrets.all() {
        let runtime_secret = Zeroizing::new(read_bounded_file(
            path,
            MAX_RUNTIME_SECRET_BYTES,
            "BACKUP_KEY_DOMAIN_CHECK_FAILED",
        )?);
        if backup_key_conflicts_with_runtime_secret(data_key, &runtime_secret)
            || backup_key_conflicts_with_runtime_secret(secrets_key, &runtime_secret)
        {
            return Err(LauncherError::new(
                "BACKUP_KEY_REUSE_REJECTED",
                "备份恢复 key 不得复用数据库密码、JWT、HMAC、KEK 或其 32-byte 十六进制编码。",
            ));
        }
    }
    Ok(())
}

fn backup_key_conflicts_with_runtime_secret(backup_key: &[u8], runtime_secret: &[u8]) -> bool {
    if constant_time_bytes_equal(backup_key, runtime_secret) {
        return true;
    }
    let Ok(raw_secret) = <&[u8; 32]>::try_from(runtime_secret) else {
        return false;
    };
    let mut encoded_secret = hex_lower_32(raw_secret);
    let conflicts = constant_time_bytes_equal(backup_key, &encoded_secret);
    encoded_secret.zeroize();
    conflicts
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn prepare_backup_staging(
    start_tools: &StartTools,
    installation: &Installation,
    sid: &str,
) -> Result<BackupStaging, LauncherError> {
    let root = installation.app_data_root.join("backup-staging");
    create_controlled_directory(&root)?;
    platform::ensure_tree_no_reparse(&root)?;
    restrict_directory_acl(start_tools, installation, &root, sid)?;
    let mut entries = fs::read_dir(&root).map_err(|_| {
        LauncherError::new(
            "BACKUP_STAGING_CHECK_FAILED",
            "无法检查明文备份 staging 目录。",
        )
    })?;
    if entries.next().is_some() {
        return Err(LauncherError::new(
            "BACKUP_STAGING_RECOVERY_REQUIRED",
            "发现上次中断遗留的备份 staging；Launcher 不会猜测或静默删除潜在数据库内容。",
        ));
    }

    let mut random = Zeroizing::new([0_u8; 16]);
    fill_random(&mut *random).map_err(|_| {
        LauncherError::new(
            "BACKUP_STAGING_RANDOM_FAILED",
            "无法为备份 staging 生成随机标识。",
        )
    })?;
    let identifier = hex_lower(&*random);
    let directory = root.join(format!(".backup-{identifier}"));
    fs::create_dir(&directory).map_err(|_| {
        LauncherError::new(
            "BACKUP_STAGING_CREATE_FAILED",
            "无法创建明文备份 staging 目录。",
        )
    })?;
    platform::ensure_tree_no_reparse(&directory)?;
    restrict_directory_acl(start_tools, installation, &directory, sid)?;
    Ok(BackupStaging {
        postgres_dump: directory.join("postgres.dump"),
        directory,
    })
}

fn cleanup_backup_staging(staging: &BackupStaging) -> Result<(), LauncherError> {
    if staging.postgres_dump.exists() {
        platform::ensure_regular_file(&staging.postgres_dump)?;
        fs::remove_file(&staging.postgres_dump).map_err(|_| {
            LauncherError::new(
                "BACKUP_STAGING_CLEANUP_FAILED",
                "无法删除明文 PostgreSQL 逻辑备份。",
            )
        })?;
    }
    let mut entries = fs::read_dir(&staging.directory).map_err(|_| {
        LauncherError::new(
            "BACKUP_STAGING_CLEANUP_FAILED",
            "无法核验备份 staging 清理状态。",
        )
    })?;
    if entries.next().is_some() {
        return Err(LauncherError::new(
            "BACKUP_STAGING_CLEANUP_FAILED",
            "备份 staging 出现未识别对象；Launcher 不会递归删除。",
        ));
    }
    fs::remove_dir(&staging.directory).map_err(|_| {
        LauncherError::new(
            "BACKUP_STAGING_CLEANUP_FAILED",
            "无法删除已清空的备份 staging 目录。",
        )
    })
}

fn perform_system_backup(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
    prepared: &PreparedBackup,
    staging: &BackupStaging,
) -> Result<(PathBuf, PathBuf), LauncherError> {
    require_active_runtime_snapshot_unchanged(installation, &prepared.active_runtime)?;
    let stop_app = compose_owned_for_runtime(
        tools,
        installation,
        image_lock,
        &prepared.active_runtime,
        &["web", "api", "worker", "egress-guard"],
        true,
        &[
            "stop",
            "--timeout",
            "30",
            "web",
            "api",
            "worker",
            "egress-guard",
        ],
        COMPOSE_TIMEOUT,
    )?;
    if !stop_app.status.success() {
        return Err(LauncherError::new(
            "BACKUP_QUIESCE_FAILED",
            "无法停止全部应用写入组件；尚未生成数据库备份。",
        ));
    }
    ensure_backup_migration_revision(tools, installation, image_lock, &prepared.active_runtime)?;
    run_postgres_dump(
        tools,
        installation,
        image_lock,
        &prepared.active_runtime,
        &staging.postgres_dump,
    )?;
    platform::ensure_regular_file(&staging.postgres_dump)?;
    restrict_file_acl(
        start_tools,
        installation,
        &staging.postgres_dump,
        &prepared.current_user_sid,
    )?;
    validate_postgres_dump_file(&staging.postgres_dump)?;

    let stop_postgres = compose_owned_for_runtime(
        tools,
        installation,
        image_lock,
        &prepared.active_runtime,
        &["postgres"],
        true,
        &["stop", "--timeout", "30", "postgres"],
        COMPOSE_TIMEOUT,
    )?;
    if !stop_postgres.status.success() {
        return Err(LauncherError::new(
            "BACKUP_POSTGRES_STOP_FAILED",
            "逻辑备份已生成，但 PostgreSQL 未能停止；尚未读取日志卷或发布备份包。",
        ));
    }

    require_active_runtime_snapshot_unchanged(installation, &prepared.active_runtime)?;

    let (data_package, data_backup_id) = export_data_package(
        tools,
        start_tools,
        installation,
        image_lock,
        prepared,
        staging,
    )?;
    require_active_runtime_snapshot_unchanged(installation, &prepared.active_runtime)?;
    match export_secrets_package(
        tools,
        start_tools,
        installation,
        image_lock,
        prepared,
        &data_backup_id,
    ) {
        Ok(secrets_package) => Ok((data_package, secrets_package)),
        Err(error) => {
            if fs::remove_file(&data_package).is_err() {
                return Err(LauncherError::new(
                    "BACKUP_PAIR_CLEANUP_FAILED",
                    format!(
                        "SECRETS 包生成失败（{}），且无法删除本次孤立 DATA 包 {}。",
                        error.code(),
                        data_package.display(),
                    ),
                ));
            }
            Err(error)
        }
    }
}

fn ensure_backup_migration_revision(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    let output = compose_owned_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
        &["postgres"],
        true,
        &[
            "exec",
            "-T",
            "postgres",
            "psql",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--username",
            "datax_studio",
            "--dbname",
            "datax_studio",
            "--command",
            "SELECT version_num FROM alembic_version;",
        ],
        PROCESS_TIMEOUT,
    )?;
    if !output.status.success()
        || normalize_text(&output.stdout).trim() != SUPPORTED_MIGRATION_REVISION
    {
        return Err(LauncherError::new(
            "BACKUP_MIGRATION_REVISION_UNSUPPORTED",
            "数据库迁移版本与当前备份 helper 不完全一致；已拒绝导出。",
        ));
    }
    Ok(())
}

fn run_postgres_dump(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
    output: &Path,
) -> Result<(), LauncherError> {
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let inventory = inspect_compose_project_inventory_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
    )?;
    require_authenticated_compose_services(&inventory, &["postgres"], true)?;
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let arguments = postgres_dump_arguments();
    let result = compose_os_to_new_file_for_runtime(
        tools,
        installation,
        active_runtime,
        &arguments,
        output,
        SYSTEM_BACKUP_TIMEOUT,
    )?;
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    if !result.status.success() {
        return Err(LauncherError::new(
            "BACKUP_PG_DUMP_FAILED",
            "pg_dump custom-format 逻辑备份失败；不会发布 DATA 包。",
        ));
    }
    Ok(())
}

fn postgres_dump_arguments() -> Vec<OsString> {
    let mut arguments = [
        "exec",
        "-T",
        "postgres",
        "pg_dump",
        "--format=custom",
        "--compress=0",
        "--no-owner",
        "--no-privileges",
        "--serializable-deferrable",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    arguments.push(OsString::from(format!(
        "--exclude-schema={BACKUP_EXCLUDED_PHASE_A_QUALIFICATION_SCHEMA}"
    )));
    arguments.extend(
        ["--username=datax_studio", "--dbname=datax_studio"]
            .into_iter()
            .map(OsString::from),
    );
    arguments
}

fn validate_postgres_dump_file(path: &Path) -> Result<(), LauncherError> {
    let metadata = fs::metadata(path)
        .map_err(|_| LauncherError::new("BACKUP_PG_DUMP_INVALID", "无法读取 pg_dump 输出。"))?;
    if metadata.len() <= 5 {
        return Err(LauncherError::new(
            "BACKUP_PG_DUMP_INVALID",
            "pg_dump 输出为空或长度无效。",
        ));
    }
    let mut prefix = [0_u8; 5];
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| LauncherError::new("BACKUP_PG_DUMP_INVALID", "无法打开 pg_dump 输出。"))?;
    file.read_exact(&mut prefix)
        .map_err(|_| LauncherError::new("BACKUP_PG_DUMP_INVALID", "无法读取 pg_dump 头。"))?;
    if &prefix != b"PGDMP" {
        return Err(LauncherError::new(
            "BACKUP_PG_DUMP_INVALID",
            "pg_dump 输出不是 PostgreSQL custom format。",
        ));
    }
    Ok(())
}

fn backup_log_volume_mount(prepared: &PreparedBackup) -> OsString {
    OsString::from(format!(
        "type=volume,source={},target=/backup/logs,readonly,volume-nocopy",
        prepared.active_runtime.volumes.logs
    ))
}

fn export_data_package(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
    prepared: &PreparedBackup,
    staging: &BackupStaging,
) -> Result<(PathBuf, String), LauncherError> {
    let mounts = vec![
        docker_bind_mount(
            &fs::canonicalize(&staging.postgres_dump).map_err(|_| {
                LauncherError::new("BACKUP_PATH_INVALID", "无法规范化 pg_dump 路径。")
            })?,
            "/backup/database/postgres.dump",
        )?,
        backup_log_volume_mount(prepared),
        docker_bind_mount(
            &fs::canonicalize(installation.install_dir.join("resources")).map_err(|_| {
                LauncherError::new("BACKUP_PATH_INVALID", "无法规范化发布元数据目录。")
            })?,
            "/backup/metadata",
        )?,
        docker_bind_mount(
            &fs::canonicalize(&prepared.active_runtime.secrets.directory).map_err(|_| {
                LauncherError::new("BACKUP_PATH_INVALID", "无法规范化运行 secret 目录。")
            })?,
            "/backup/secrets",
        )?,
        docker_writable_bind_mount(&prepared.data_output, "/backup/output")?,
    ];
    let helper = backup_helper_container(BACKUP_DATA_HELPER_ROLE, prepared);
    let mut arguments = backup_container_arguments(&image_lock.worker, &mounts, &helper);
    arguments.extend([
        OsString::from("export-data"),
        OsString::from("--output-dir"),
        OsString::from("/backup/output"),
        OsString::from("--installation-id"),
        OsString::from(&prepared.installation_id),
        OsString::from("--product-version"),
        OsString::from(env!("CARGO_PKG_VERSION")),
        OsString::from("--migration-revision"),
        OsString::from(SUPPORTED_MIGRATION_REVISION),
        OsString::from("--metadata-root"),
        OsString::from("/backup/metadata"),
        OsString::from("--postgres-dump"),
        OsString::from("/backup/database/postgres.dump"),
        OsString::from("--des-log-data"),
        OsString::from("/backup/logs"),
        OsString::from("--secret-root-for-scan"),
        OsString::from("/backup/secrets"),
    ]);
    run_helper_with_cleanup(
        tools,
        installation,
        &helper,
        &arguments,
        backup_password_stdin(&prepared.data_key),
        |mut output| {
            output.stderr.zeroize();
            validate_system_backup_result(
                output,
                start_tools,
                installation,
                &prepared.data_output,
                "DATA",
                ".dxdata",
                &prepared.current_user_sid,
            )
        },
    )
}

fn export_secrets_package(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
    prepared: &PreparedBackup,
    related_data_backup_id: &str,
) -> Result<PathBuf, LauncherError> {
    let mounts = vec![
        docker_bind_mount(
            &fs::canonicalize(&prepared.active_runtime.secrets.directory).map_err(|_| {
                LauncherError::new("BACKUP_PATH_INVALID", "无法规范化运行 secret 目录。")
            })?,
            "/backup/secrets",
        )?,
        docker_writable_bind_mount(&prepared.secrets_output, "/backup/output")?,
    ];
    let helper = backup_helper_container(BACKUP_SECRETS_HELPER_ROLE, prepared);
    let mut arguments = backup_container_arguments(&image_lock.worker, &mounts, &helper);
    arguments.extend([
        OsString::from("export-secrets"),
        OsString::from("--output-dir"),
        OsString::from("/backup/output"),
        OsString::from("--installation-id"),
        OsString::from(&prepared.installation_id),
        OsString::from("--product-version"),
        OsString::from(env!("CARGO_PKG_VERSION")),
        OsString::from("--migration-revision"),
        OsString::from(SUPPORTED_MIGRATION_REVISION),
        OsString::from("--related-data-backup-id"),
        OsString::from(related_data_backup_id),
        OsString::from("--secret-root"),
        OsString::from("/backup/secrets"),
    ]);
    run_helper_with_cleanup(
        tools,
        installation,
        &helper,
        &arguments,
        backup_password_stdin(&prepared.secrets_key),
        |mut output| {
            output.stderr.zeroize();
            validate_system_backup_result(
                output,
                start_tools,
                installation,
                &prepared.secrets_output,
                "SECRETS",
                ".dxkeys",
                &prepared.current_user_sid,
            )
            .map(|(path, _)| path)
        },
    )
}

fn backup_helper_container(role: &'static str, prepared: &PreparedBackup) -> HelperContainer {
    helper_container_identity(
        role,
        &[
            &prepared.installation_id,
            &prepared.active_runtime.generation.generation_id,
            &prepared.active_runtime.generation.state_sha256,
            &prepared.current_user_sid,
        ],
    )
}

fn restore_stage_helper_container(prepared: &PreparedRestore) -> HelperContainer {
    let data_input = prepared.data_input.to_string_lossy();
    let secrets_input = prepared.secrets_input.to_string_lossy();
    let staging_root = prepared.staging_root.to_string_lossy();
    helper_container_identity(
        RESTORE_STAGE_HELPER_ROLE,
        &[
            &prepared.current_user_sid,
            data_input.as_ref(),
            secrets_input.as_ref(),
            staging_root.as_ref(),
        ],
    )
}

fn helper_container_identity(role: &'static str, identity_fields: &[&str]) -> HelperContainer {
    let mut digest = Sha256::new();
    digest.update(b"DataXEnterpriseStudio.helper-container.v1\0");
    digest.update(role.as_bytes());
    for field in identity_fields {
        digest.update([0]);
        digest.update(field.as_bytes());
    }
    let digest = hex_lower(&digest.finalize());
    let opaque_id = digest[..32].to_owned();
    HelperContainer {
        name: format!("des-{role}-{opaque_id}"),
        role,
        opaque_id,
    }
}

fn backup_container_arguments(
    image: &str,
    mounts: &[OsString],
    helper: &HelperContainer,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--pull=never"),
        OsString::from("--name"),
        OsString::from(&helper.name),
        OsString::from("--label"),
        OsString::from(format!("{HELPER_CONTAINER_ROLE_LABEL}={}", helper.role)),
        OsString::from("--label"),
        OsString::from(format!("{HELPER_CONTAINER_ID_LABEL}={}", helper.opaque_id)),
        OsString::from("--network"),
        OsString::from("none"),
        OsString::from("--read-only"),
        OsString::from("--cap-drop"),
        OsString::from("ALL"),
        OsString::from("--security-opt"),
        OsString::from("no-new-privileges:true"),
        OsString::from("--pids-limit"),
        OsString::from("64"),
        OsString::from("--memory"),
        OsString::from("512m"),
        OsString::from("--cpus"),
        OsString::from("1"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp:rw,noexec,nosuid,size=16m"),
    ];
    for mount in mounts {
        arguments.push(OsString::from("--mount"));
        arguments.push(mount.clone());
    }
    arguments.extend([
        OsString::from("--entrypoint"),
        OsString::from("datax-studio-system-backup"),
        OsString::from(image),
    ]);
    arguments
}

fn restore_stage_container_arguments(
    image: &str,
    mounts: &[OsString],
    helper: &HelperContainer,
) -> Vec<OsString> {
    let mut arguments = backup_container_arguments(image, mounts, helper);
    let insertion = arguments.len().saturating_sub(3);
    arguments.splice(
        insertion..insertion,
        [
            OsString::from("--label"),
            OsString::from("com.xiaoli.datax.restore-role=stage-pair"),
        ],
    );
    arguments
}

fn run_helper_with_cleanup<T>(
    tools: &Tools,
    installation: &Installation,
    helper: &HelperContainer,
    arguments: &[OsString],
    secret_stdin: Zeroizing<Vec<u8>>,
    validate: impl FnOnce(ProcessOutput) -> Result<T, LauncherError>,
) -> Result<T, LauncherError> {
    let operation = run_process_with_secret_stdin(
        &tools.docker,
        arguments,
        &tools.docker_environment(),
        &installation.install_dir,
        SYSTEM_BACKUP_TIMEOUT,
        secret_stdin,
    )
    .and_then(validate);
    complete_helper_operation(tools, installation, helper, operation)
}

fn run_named_container_with_cleanup<T>(
    tools: &Tools,
    installation: &Installation,
    helper: &HelperContainer,
    arguments: &[OsString],
    timeout: Duration,
    validate: impl FnOnce(ProcessOutput) -> Result<T, LauncherError>,
) -> Result<T, LauncherError> {
    let operation = run_process(
        &tools.docker,
        arguments,
        &tools.docker_environment(),
        &installation.install_dir,
        timeout,
    )
    .and_then(validate);
    complete_helper_operation(tools, installation, helper, operation)
}

fn complete_helper_operation<T>(
    tools: &Tools,
    installation: &Installation,
    helper: &HelperContainer,
    operation: Result<T, LauncherError>,
) -> Result<T, LauncherError> {
    match operation {
        Ok(value) => Ok(value),
        Err(primary) => Err(merge_helper_cleanup_result(
            primary,
            helper,
            cleanup_helper_container(tools, installation, helper),
        )),
    }
}

fn merge_helper_cleanup_result(
    primary: LauncherError,
    helper: &HelperContainer,
    cleanup: Result<(), LauncherError>,
) -> LauncherError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup_error) => LauncherError::new(
            "HELPER_CLEANUP_FAILED",
            format!(
                "受控 {} helper 失败（{}），且其 Docker 容器的身份核验或强制清理失败（{}）。请停止使用本机并人工处置；Launcher 不会把该操作报告为成功。",
                helper.role,
                primary.code(),
                cleanup_error.code(),
            ),
        ),
    }
}

fn cleanup_helper_container(
    tools: &Tools,
    installation: &Installation,
    helper: &HelperContainer,
) -> Result<(), LauncherError> {
    let Some(container_id) = find_named_helper_container_id(tools, installation, helper)? else {
        return Ok(());
    };

    let inspected = docker(
        tools,
        installation,
        &[
            "container",
            "inspect",
            "--format",
            HELPER_CONTAINER_INSPECT_FORMAT,
            &container_id,
        ],
        PROCESS_TIMEOUT,
    );
    let inspected = match inspected {
        Ok(output) if output.status.success() => output,
        Ok(_) | Err(_) => {
            return helper_cleanup_id_gone_or_error(
                tools,
                installation,
                helper,
                &container_id,
                "无法读取受控 helper 容器的不可变身份标签。",
            );
        }
    };
    let expected_labels = format!("{}|{}", helper.role, helper.opaque_id);
    if normalize_text(&inspected.stdout).trim() != expected_labels {
        return Err(LauncherError::new(
            "HELPER_CLEANUP_IDENTITY_MISMATCH",
            "同名 Docker 容器的受控 helper 标签不匹配；Launcher 不会删除未验证容器。",
        ));
    }

    let removed = docker(
        tools,
        installation,
        &["container", "rm", "--force", &container_id],
        PROCESS_TIMEOUT,
    );
    match removed {
        Ok(output) if output.status.success() => {}
        Ok(_) | Err(_) => {
            return helper_cleanup_id_gone_or_error(
                tools,
                installation,
                helper,
                &container_id,
                "无法强制停止并删除已验证的受控 helper 容器。",
            );
        }
    }
    if find_named_helper_container_id(tools, installation, helper)?.is_some() {
        return Err(LauncherError::new(
            "HELPER_CLEANUP_VERIFY_FAILED",
            "强制清理后仍检测到同名 helper 容器；Launcher 已安全阻断。",
        ));
    }
    Ok(())
}

fn helper_cleanup_id_gone_or_error(
    tools: &Tools,
    installation: &Installation,
    helper: &HelperContainer,
    expected_id: &str,
    message: &str,
) -> Result<(), LauncherError> {
    match find_named_helper_container_id(tools, installation, helper) {
        Ok(None) => Ok(()),
        Ok(Some(actual_id)) if actual_id == expected_id => {
            Err(LauncherError::new("HELPER_CLEANUP_REMOVE_FAILED", message))
        }
        Ok(Some(_)) => Err(LauncherError::new(
            "HELPER_CLEANUP_IDENTITY_MISMATCH",
            "受控 helper 的名称在清理期间被重用；Launcher 不会删除新的未验证容器。",
        )),
        Err(_) => Err(LauncherError::new(
            "HELPER_CLEANUP_INSPECTION_FAILED",
            "无法确认失败 helper 容器是否已经消失；Launcher 已安全阻断。",
        )),
    }
}

fn find_named_helper_container_id(
    tools: &Tools,
    installation: &Installation,
    helper: &HelperContainer,
) -> Result<Option<String>, LauncherError> {
    let name_filter = format!("name=^/{}$", helper.name);
    let listed = docker(
        tools,
        installation,
        &[
            "container",
            "ls",
            "--all",
            "--filter",
            &name_filter,
            "--format",
            "{{.ID}}",
        ],
        PROCESS_TIMEOUT,
    )
    .map_err(|_| {
        LauncherError::new(
            "HELPER_CLEANUP_INSPECTION_FAILED",
            "无法枚举失败 helper 容器；Launcher 已安全阻断。",
        )
    })?;
    if !listed.status.success() {
        return Err(LauncherError::new(
            "HELPER_CLEANUP_INSPECTION_FAILED",
            "Docker 拒绝枚举失败 helper 容器；Launcher 已安全阻断。",
        ));
    }
    parse_helper_container_id(&listed.stdout)
}

fn parse_helper_container_id(output: &[u8]) -> Result<Option<String>, LauncherError> {
    let normalized = normalize_text(output);
    let ids = normalized
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    match ids.as_slice() {
        [] => Ok(None),
        [identifier]
            if (12..=64).contains(&identifier.len())
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Ok(Some((*identifier).to_owned()))
        }
        _ => Err(LauncherError::new(
            "HELPER_CLEANUP_IDENTITY_INVALID",
            "Docker 返回了多个或格式无效的同名 helper 容器身份；Launcher 不会猜测删除目标。",
        )),
    }
}

fn docker_bind_mount(source: &Path, target: &str) -> Result<OsString, LauncherError> {
    docker_bind_mount_with_mode(source, target, true)
}

fn docker_writable_bind_mount(source: &Path, target: &str) -> Result<OsString, LauncherError> {
    docker_bind_mount_with_mode(source, target, false)
}

fn docker_bind_mount_with_mode(
    source: &Path,
    target: &str,
    read_only: bool,
) -> Result<OsString, LauncherError> {
    let value = source.to_str().ok_or_else(|| {
        LauncherError::new(
            "BACKUP_PATH_INVALID",
            "Docker 备份挂载路径不是有效 Unicode。",
        )
    })?;
    let value = value.strip_prefix(r"\\?\").unwrap_or(value);
    if value.contains([',', '\r', '\n', '\0']) {
        return Err(LauncherError::new(
            "BACKUP_PATH_INVALID",
            "Docker 备份挂载路径包含不受支持的分隔字符。",
        ));
    }
    let mode = if read_only { ",readonly" } else { "" };
    Ok(OsString::from(format!(
        "type=bind,source={value},target={target}{mode}"
    )))
}

fn backup_password_stdin(key: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut stdin = Zeroizing::new(Vec::with_capacity(key.len() + 1));
    stdin.extend_from_slice(key);
    stdin.push(b'\n');
    stdin
}

fn validate_system_backup_result(
    output: ProcessOutput,
    start_tools: &StartTools,
    installation: &Installation,
    output_directory: &Path,
    expected_kind: &str,
    expected_suffix: &str,
    sid: &str,
) -> Result<(PathBuf, String), LauncherError> {
    if !output.status.success() {
        return Err(LauncherError::new(
            "BACKUP_HELPER_FAILED",
            format!("{expected_kind} 备份 helper 失败；未报告成功。"),
        ));
    }
    let result: SystemBackupResult = serde_json::from_slice(&output.stdout).map_err(|_| {
        LauncherError::new(
            "BACKUP_HELPER_RESPONSE_INVALID",
            "备份 helper 未返回严格的成功 JSON。",
        )
    })?;
    if !system_backup_result_valid(&result, expected_kind, expected_suffix) {
        return Err(LauncherError::new(
            "BACKUP_HELPER_RESPONSE_INVALID",
            "备份 helper 成功 JSON 的类型、标识、文件名或摘要字段无效。",
        ));
    }
    let package = output_directory.join(&result.filename);
    platform::ensure_regular_file(&package)?;
    restrict_file_acl(start_tools, installation, &package, sid)?;
    let (size, digest) = sha256_regular_file(&package)?;
    if size != result.package_bytes || !constant_time_ascii_equal(&digest, &result.package_sha256) {
        return Err(LauncherError::new(
            "BACKUP_PACKAGE_INTEGRITY_FAILED",
            "宿主备份包长度或 SHA-256 与 helper 结果不一致。",
        ));
    }
    Ok((package, result.backup_id))
}

fn system_backup_result_valid(
    result: &SystemBackupResult,
    expected_kind: &str,
    expected_suffix: &str,
) -> bool {
    let expected_filename = format!("{}{}", result.backup_id, expected_suffix);
    result.schema_version == "1.0"
        && result.code == "BACKUP_CREATED"
        && result.kind == expected_kind
        && result.backup_id.len() == 32
        && result
            .backup_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && result.filename == expected_filename
        && result.package_bytes > 0
        && is_sha256(&result.package_sha256)
}

fn sha256_regular_file(path: &Path) -> Result<(u64, String), LauncherError> {
    platform::ensure_regular_file(path)?;
    let before = fs::metadata(path)
        .map_err(|_| LauncherError::new("BACKUP_PACKAGE_READ_FAILED", "无法读取备份包元数据。"))?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| LauncherError::new("BACKUP_PACKAGE_READ_FAILED", "无法打开备份包。"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| LauncherError::new("BACKUP_PACKAGE_READ_FAILED", "读取备份包失败。"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| LauncherError::new("BACKUP_PACKAGE_READ_FAILED", "备份包长度溢出。"))?;
        digest.update(&buffer[..read]);
    }
    let after = fs::metadata(path)
        .map_err(|_| LauncherError::new("BACKUP_PACKAGE_READ_FAILED", "无法复核备份包元数据。"))?;
    if before.len() != after.len() || total != after.len() {
        return Err(LauncherError::new(
            "BACKUP_PACKAGE_CHANGED",
            "备份包在宿主校验期间发生变化。",
        ));
    }
    Ok((total, hex_lower(&digest.finalize())))
}

fn resume_services_after_system_backup(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let up = compose_owned_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
        &[],
        false,
        &COMPOSE_UP_WITHOUT_PULL,
        COMPOSE_TIMEOUT,
    )?;
    if !up.status.success() {
        return Err(LauncherError::new(
            "BACKUP_RESUME_FAILED",
            "备份后 Docker Compose 无法重新启动。",
        ));
    }
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let volume_contract = active_runtime.volume_contract();
    validate_active_runtime_volume_contract(tools, installation, &volume_contract)?;
    validate_actual_compose_ports_for_runtime(
        tools,
        start_tools,
        installation,
        image_lock,
        active_runtime,
    )?;
    verify_shared_network_namespace_for_runtime(tools, installation, image_lock, active_runtime)?;
    wait_for_http(LIVE_PATH, LIVE_TIMEOUT, "BACKUP_RESUME_LIVE_TIMEOUT")?;
    verify_container_secret_targets_for_runtime(tools, installation, image_lock, active_runtime)?;
    let resume = lifecycle_for_runtime(tools, installation, image_lock, active_runtime, "resume")?;
    if !resume.safe_to_stop {
        return Err(LauncherError::new(
            "BACKUP_RECONCILIATION_REQUIRED",
            "备份后恢复对账尚未完成，系统保持 draining。",
        ));
    }
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    wait_for_http(READY_PATH, READY_TIMEOUT, "BACKUP_RESUME_READY_TIMEOUT")
}

fn stop(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    force: bool,
) -> Result<(), LauncherError> {
    if inspect_compose_project_inventory(tools, installation, image_lock)?.is_empty() {
        return Ok(());
    }
    if force {
        if !platform::confirm_force_stop() {
            return Err(LauncherError::new(
                "FORCE_STOP_CANCELED",
                "用户取消了强制停止；服务状态未改变。",
            ));
        }
    } else {
        let preflight = lifecycle(tools, installation, image_lock, "preflight-stop")?;
        if !preflight.safe_to_stop {
            return Err(LauncherError::new(
                "ACTIVE_ATTEMPTS_PRESENT",
                format!(
                    "安全停止被拒绝：仍有 {} 个活动执行和 {} 个活动恢复探针。请等待完成或先取消；如确需中断，请显式使用 stop --force。",
                    preflight.active_execution_count, preflight.active_probe_count
                ),
            ));
        }
    }

    let down = compose_owned(
        tools,
        installation,
        image_lock,
        &[],
        false,
        &["down", "--timeout", "30"],
        COMPOSE_TIMEOUT,
    )?;
    if !down.status.success() {
        return Err(LauncherError::new(
            "COMPOSE_STOP_FAILED",
            "Docker Compose 停止失败；named volumes 未被删除。",
        ));
    }
    Ok(())
}

fn compose_project_ownership_unverified() -> LauncherError {
    LauncherError::new(
        "COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED",
        "无法证明现有 Compose 容器属于当前签名发布、固定镜像和当前 installation-id；Launcher 不会执行 up、exec、stop、down 或自动清理。",
    )
}

fn inspect_compose_project_inventory(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<ComposeProjectInventory, LauncherError> {
    let active_runtime = load_active_runtime_snapshot(installation)?;
    inspect_compose_project_inventory_for_runtime(tools, installation, image_lock, &active_runtime)
}

fn inspect_compose_project_inventory_for_runtime(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<ComposeProjectInventory, LauncherError> {
    let ids = list_compose_project_container_ids(tools, installation)?;
    if ids.is_empty() {
        return Ok(ComposeProjectInventory::Empty);
    }

    let volume_contract = active_runtime.volume_contract();
    validate_active_runtime_volume_contract(tools, installation, &volume_contract)
        .map_err(|_| compose_project_ownership_unverified())?;
    let containers = inspect_compose_project_containers(tools, installation, &ids)?;
    validate_compose_project_inventory(containers, image_lock, &volume_contract.names)
}

fn list_compose_project_container_ids(
    tools: &Tools,
    installation: &Installation,
) -> Result<Vec<String>, LauncherError> {
    let project_filter = format!("label={COMPOSE_PROJECT_LABEL}={COMPOSE_PROJECT}");
    let output = docker(
        tools,
        installation,
        &[
            "ps",
            "--all",
            "--filter",
            &project_filter,
            "--format",
            "{{.ID}}",
        ],
        PROCESS_TIMEOUT,
    )
    .map_err(|_| compose_project_ownership_unverified())?;
    if !output.status.success() {
        return Err(compose_project_ownership_unverified());
    }
    parse_compose_project_container_ids(&output.stdout)
}

fn parse_compose_project_container_ids(output: &[u8]) -> Result<Vec<String>, LauncherError> {
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();
    let normalized = normalize_text(output);
    for identifier in normalized
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !is_docker_container_identifier(identifier) || !seen.insert(identifier.to_owned()) {
            return Err(compose_project_ownership_unverified());
        }
        ids.push(identifier.to_owned());
    }
    Ok(ids)
}

fn inspect_compose_project_containers(
    tools: &Tools,
    installation: &Installation,
    ids: &[String],
) -> Result<Vec<InspectedComposeContainer>, LauncherError> {
    let mut arguments = vec![
        "inspect".to_owned(),
        "--format".to_owned(),
        COMPOSE_CONTAINER_INVENTORY_FORMAT.to_owned(),
    ];
    arguments.extend(ids.iter().cloned());
    let argument_references = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let output = docker(tools, installation, &argument_references, PROCESS_TIMEOUT)
        .map_err(|_| compose_project_ownership_unverified())?;
    if !output.status.success() {
        return Err(compose_project_ownership_unverified());
    }
    parse_compose_project_container_inspections(&output.stdout, ids)
}

fn parse_compose_project_container_inspections(
    output: &[u8],
    expected_ids: &[String],
) -> Result<Vec<InspectedComposeContainer>, LauncherError> {
    let normalized = normalize_text(output);
    let lines = normalized
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != expected_ids.len() {
        return Err(compose_project_ownership_unverified());
    }
    let expected = expected_ids.iter().cloned().collect::<BTreeSet<_>>();
    if expected.len() != expected_ids.len() {
        return Err(compose_project_ownership_unverified());
    }

    let mut seen = BTreeSet::new();
    let mut containers = Vec::with_capacity(lines.len());
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(compose_project_ownership_unverified());
        }
        let id = serde_json::from_str::<String>(fields[0])
            .map_err(|_| compose_project_ownership_unverified())?;
        let image = serde_json::from_str::<String>(fields[1])
            .map_err(|_| compose_project_ownership_unverified())?;
        let labels = serde_json::from_str::<BTreeMap<String, String>>(fields[2])
            .map_err(|_| compose_project_ownership_unverified())?;
        let mounts = serde_json::from_str::<Vec<ComposeContainerMount>>(fields[3])
            .map_err(|_| compose_project_ownership_unverified())?;
        let running = serde_json::from_str::<bool>(fields[4])
            .map_err(|_| compose_project_ownership_unverified())?;
        if !is_docker_container_identifier(&id)
            || !expected.contains(&id)
            || !seen.insert(id.clone())
        {
            return Err(compose_project_ownership_unverified());
        }
        containers.push(InspectedComposeContainer {
            id,
            image,
            labels,
            mounts,
            running,
        });
    }
    Ok(containers)
}

fn validate_compose_project_inventory(
    containers: Vec<InspectedComposeContainer>,
    image_lock: &ImageLock,
    volume_names: &RuntimeVolumeNames,
) -> Result<ComposeProjectInventory, LauncherError> {
    if containers.is_empty() {
        return Ok(ComposeProjectInventory::Empty);
    }

    let mut services = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for container in containers {
        let service = container
            .labels
            .get(COMPOSE_SERVICE_LABEL)
            .filter(|service| EXPECTED_SERVICES.contains(&service.as_str()))
            .ok_or_else(compose_project_ownership_unverified)?;
        if container
            .labels
            .get(COMPOSE_PROJECT_LABEL)
            .map(String::as_str)
            != Some(COMPOSE_PROJECT)
            || image_lock.for_service(service) != Some(container.image.as_str())
            || !runtime_volume_mounts_match(service, &container.mounts, volume_names)
            || !ids.insert(container.id.clone())
            || services.contains_key(service)
        {
            return Err(compose_project_ownership_unverified());
        }
        services.insert(
            service.to_owned(),
            AuthenticatedComposeContainer {
                id: container.id,
                running: container.running,
            },
        );
    }
    Ok(ComposeProjectInventory::Verified(services))
}

fn runtime_volume_mounts_match(
    service: &str,
    mounts: &[ComposeContainerMount],
    volume_names: &RuntimeVolumeNames,
) -> bool {
    let mut actual = BTreeSet::new();
    for mount in mounts.iter().filter(|mount| mount.kind == "volume") {
        let Some(name) = mount.name.as_deref() else {
            return false;
        };
        if !mount.read_write || !actual.insert((name.to_owned(), mount.destination.clone())) {
            return false;
        }
    }
    let expected = expected_runtime_volume_mounts(service, volume_names);
    actual == expected
}

fn expected_runtime_volume_mounts(
    service: &str,
    volume_names: &RuntimeVolumeNames,
) -> BTreeSet<(String, String)> {
    match service {
        "postgres" => BTreeSet::from([(
            volume_names.postgres.clone(),
            String::from("/var/lib/postgresql/data"),
        )]),
        "api" => BTreeSet::from([(
            volume_names.logs.clone(),
            String::from("/var/lib/datax-studio/logs"),
        )]),
        "worker" => BTreeSet::from([
            (
                volume_names.logs.clone(),
                String::from("/var/lib/datax-studio/logs"),
            ),
            (
                volume_names.workspace.clone(),
                String::from("/var/lib/datax-studio/runs"),
            ),
        ]),
        "migrate" | "egress-guard" | "web" => BTreeSet::new(),
        _ => BTreeSet::from([(String::from("invalid"), String::from("invalid"))]),
    }
}

fn is_docker_container_identifier(value: &str) -> bool {
    (12..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_authenticated_compose_services(
    inventory: &ComposeProjectInventory,
    required_services: &[&str],
    require_complete: bool,
) -> Result<(), LauncherError> {
    if inventory.is_empty()
        || required_services
            .iter()
            .any(|service| !inventory.has_service(service))
        || (require_complete && !inventory.is_complete())
    {
        return Err(compose_project_ownership_unverified());
    }
    Ok(())
}

fn compose_owned(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    required_services: &[&str],
    require_complete: bool,
    arguments: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    let inventory = inspect_compose_project_inventory(tools, installation, image_lock)?;
    if inventory.is_empty() && required_services.is_empty() && !require_complete {
        return compose(tools, installation, arguments, timeout);
    }
    require_authenticated_compose_services(&inventory, required_services, require_complete)?;
    compose(tools, installation, arguments, timeout)
}

#[allow(clippy::too_many_arguments)]
fn compose_owned_for_runtime(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
    required_services: &[&str],
    require_complete: bool,
    arguments: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let inventory = inspect_compose_project_inventory_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
    )?;
    if inventory.is_empty() && required_services.is_empty() && !require_complete {
        require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
        let output = compose_for_runtime(tools, installation, active_runtime, arguments, timeout)?;
        require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
        return Ok(output);
    }
    require_authenticated_compose_services(&inventory, required_services, require_complete)?;
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let output = compose_for_runtime(tools, installation, active_runtime, arguments, timeout)?;
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    Ok(output)
}

fn lifecycle(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    command: &str,
) -> Result<StopPreflight, LauncherError> {
    let output = compose_owned(
        tools,
        installation,
        image_lock,
        &["api"],
        true,
        &[
            "exec",
            "-T",
            "api",
            "python",
            "-m",
            "datax_studio.lifecycle",
            command,
            "--json",
        ],
        COMPOSE_TIMEOUT,
    )?;
    let parsed: StopPreflight = serde_json::from_slice(&output.stdout).map_err(|_| {
        LauncherError::new(
            "LIFECYCLE_RESPONSE_INVALID",
            "容器 lifecycle helper 未返回有效 JSON；已安全阻断。",
        )
    })?;
    match (
        output.status.code(),
        parsed.safe_to_stop,
        parsed.code.as_str(),
    ) {
        (Some(0), true, "SAFE_TO_STOP") => Ok(parsed),
        (Some(3), false, "ACTIVE_ATTEMPTS_PRESENT") => Ok(parsed),
        _ => Err(LauncherError::new(
            "LIFECYCLE_HELPER_FAILED",
            "容器 lifecycle helper 执行失败或返回矛盾状态；已安全阻断。",
        )),
    }
}

fn lifecycle_for_runtime(
    tools: &Tools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
    command: &str,
) -> Result<StopPreflight, LauncherError> {
    let output = compose_owned_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
        &["api"],
        true,
        &[
            "exec",
            "-T",
            "api",
            "python",
            "-m",
            "datax_studio.lifecycle",
            command,
            "--json",
        ],
        COMPOSE_TIMEOUT,
    )?;
    let parsed: StopPreflight = serde_json::from_slice(&output.stdout).map_err(|_| {
        LauncherError::new(
            "LIFECYCLE_RESPONSE_INVALID",
            "容器 lifecycle helper 未返回有效 JSON；已安全阻断。",
        )
    })?;
    match (
        output.status.code(),
        parsed.safe_to_stop,
        parsed.code.as_str(),
    ) {
        (Some(0), true, "SAFE_TO_STOP") => Ok(parsed),
        (Some(3), false, "ACTIVE_ATTEMPTS_PRESENT") => Ok(parsed),
        _ => Err(LauncherError::new(
            "LIFECYCLE_HELPER_FAILED",
            "容器 lifecycle helper 执行失败或返回矛盾状态；已安全阻断。",
        )),
    }
}

fn docker(
    tools: &Tools,
    installation: &Installation,
    arguments: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
    let environment = tools.docker_environment();
    run_process(
        &tools.docker,
        &arguments,
        &environment,
        &installation.install_dir,
        timeout,
    )
}

fn compose(
    tools: &Tools,
    installation: &Installation,
    arguments: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
    compose_os(tools, installation, &arguments, timeout)
}

fn compose_for_runtime(
    tools: &Tools,
    installation: &Installation,
    active_runtime: &ActiveRuntimeSnapshot,
    arguments: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
    compose_os_for_runtime(tools, installation, active_runtime, &arguments, timeout)
}

fn compose_os(
    tools: &Tools,
    installation: &Installation,
    arguments: &[OsString],
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    let mut all = vec![
        OsString::from("--env-file"),
        installation.image_env_file.as_os_str().to_os_string(),
        OsString::from("--project-name"),
        OsString::from(COMPOSE_PROJECT),
        OsString::from("--file"),
        installation.compose_file.as_os_str().to_os_string(),
    ];
    all.extend(arguments.iter().cloned());
    let mut environment = installation.compose_environment()?;
    environment.extend(tools.docker_environment());
    run_process(
        &tools.compose,
        &all,
        &environment,
        &installation.install_dir,
        timeout,
    )
}

fn compose_os_for_runtime(
    tools: &Tools,
    installation: &Installation,
    active_runtime: &ActiveRuntimeSnapshot,
    arguments: &[OsString],
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    let mut all = vec![
        OsString::from("--env-file"),
        installation.image_env_file.as_os_str().to_os_string(),
        OsString::from("--project-name"),
        OsString::from(COMPOSE_PROJECT),
        OsString::from("--file"),
        installation.compose_file.as_os_str().to_os_string(),
    ];
    all.extend(arguments.iter().cloned());
    let mut environment = installation.compose_environment_for(active_runtime);
    environment.extend(tools.docker_environment());
    run_process(
        &tools.compose,
        &all,
        &environment,
        &installation.install_dir,
        timeout,
    )
}

fn compose_os_to_new_file_for_runtime(
    tools: &Tools,
    installation: &Installation,
    active_runtime: &ActiveRuntimeSnapshot,
    arguments: &[OsString],
    output: &Path,
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    let mut all = vec![
        OsString::from("--env-file"),
        installation.image_env_file.as_os_str().to_os_string(),
        OsString::from("--project-name"),
        OsString::from(COMPOSE_PROJECT),
        OsString::from("--file"),
        installation.compose_file.as_os_str().to_os_string(),
    ];
    all.extend(arguments.iter().cloned());
    let mut environment = installation.compose_environment_for(active_runtime);
    environment.extend(tools.docker_environment());
    run_process_to_new_file(
        &tools.compose,
        &all,
        &environment,
        &installation.install_dir,
        timeout,
        output,
    )
}

fn compose_with_secret_stdin(
    tools: &Tools,
    installation: &Installation,
    arguments: &[OsString],
    timeout: Duration,
    secret_stdin: Zeroizing<Vec<u8>>,
) -> Result<ProcessOutput, LauncherError> {
    let mut all = vec![
        OsString::from("--env-file"),
        installation.image_env_file.as_os_str().to_os_string(),
        OsString::from("--project-name"),
        OsString::from(COMPOSE_PROJECT),
        OsString::from("--file"),
        installation.compose_file.as_os_str().to_os_string(),
    ];
    all.extend(arguments.iter().cloned());
    let mut environment = installation.compose_environment()?;
    environment.extend(tools.docker_environment());
    run_process_with_secret_stdin(
        &tools.compose,
        &all,
        &environment,
        &installation.install_dir,
        timeout,
        secret_stdin,
    )
}

fn query_registry_string(
    reg: &Path,
    working_directory: &Path,
    key: &str,
    value_name: &str,
) -> Result<Option<String>, LauncherError> {
    let output = run_process(
        reg,
        &[
            OsString::from("query"),
            OsString::from(key),
            OsString::from("/v"),
            OsString::from(value_name),
            OsString::from("/reg:64"),
        ],
        &[],
        working_directory,
        PROCESS_TIMEOUT,
    )?;
    if !output.status.success() {
        return Ok(None);
    }
    extract_registry_string(&normalize_text(&output.stdout), value_name)
        .map(Some)
        .ok_or_else(|| {
            LauncherError::new("REGISTRY_VALUE_INVALID", "受信注册表值存在，但格式无效。")
        })
}

fn extract_registry_string(output: &str, value_name: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let mut fields = trimmed.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case(value_name) {
            continue;
        }
        if !fields.next()?.eq_ignore_ascii_case("REG_SZ") {
            return None;
        }
        let marker = trimmed.to_ascii_uppercase().find("REG_SZ")?;
        let value = trimmed[marker + "REG_SZ".len()..].trim();
        if value.is_empty() || value.contains('\0') {
            return None;
        }
        return Some(value.to_owned());
    }
    None
}

fn read_bounded_file(path: &Path, limit: u64, error_code: &str) -> Result<Vec<u8>, LauncherError> {
    let metadata =
        fs::metadata(path).map_err(|_| LauncherError::new(error_code, "无法读取受控发布资源。"))?;
    if metadata.len() > limit {
        return Err(LauncherError::new(error_code, "受控发布资源超过大小上限。"));
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| LauncherError::new(error_code, "无法打开受控发布资源。"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LauncherError::new(error_code, "读取受控发布资源失败。"))?;
    if bytes.len() as u64 > limit {
        return Err(LauncherError::new(
            error_code,
            "受控发布资源在读取期间超过大小上限。",
        ));
    }
    Ok(bytes)
}

fn parse_image_lock(bytes: &[u8]) -> Result<ImageLock, LauncherError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        LauncherError::new(
            "IMAGE_LOCK_INVALID",
            "发布镜像锁必须是无 BOM 的 UTF-8 文本。",
        )
    })?;
    if text.starts_with('\u{feff}') {
        return Err(LauncherError::new(
            "IMAGE_LOCK_INVALID",
            "发布镜像锁不得包含 BOM。",
        ));
    }
    let mut values = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| LauncherError::new("IMAGE_LOCK_INVALID", "发布镜像锁包含无效行。"))?;
        if key.trim() != key || value.trim() != value || values.contains_key(key) {
            return Err(LauncherError::new(
                "IMAGE_LOCK_INVALID",
                "发布镜像锁包含空白、重复键或不规范值。",
            ));
        }
        let expected_repository = IMAGE_RULES
            .iter()
            .find_map(|(expected_key, repository)| (*expected_key == key).then_some(*repository))
            .ok_or_else(|| {
                LauncherError::new("IMAGE_LOCK_INVALID", "发布镜像锁包含未允许的键。")
            })?;
        if !is_pinned_image(value, expected_repository) {
            return Err(LauncherError::new(
                "IMAGE_LOCK_INVALID",
                "发布镜像必须匹配固定仓库并使用 sha256 摘要，tag 或自定义仓库被拒绝。",
            ));
        }
        values.insert(key.to_owned(), value.to_owned());
    }
    if values.len() != IMAGE_RULES.len() {
        return Err(LauncherError::new(
            "IMAGE_LOCK_INVALID",
            "发布镜像锁缺少固定镜像。",
        ));
    }
    Ok(ImageLock {
        postgres: values.remove("DES_POSTGRES_IMAGE").unwrap(),
        api: values.remove("DES_API_IMAGE").unwrap(),
        egress_guard: values.remove("DES_EGRESS_GUARD_IMAGE").unwrap(),
        worker: values.remove("DES_WORKER_IMAGE").unwrap(),
        web: values.remove("DES_WEB_IMAGE").unwrap(),
    })
}

fn is_pinned_image(value: &str, repository: &str) -> bool {
    value
        .strip_prefix(repository)
        .and_then(|suffix| suffix.strip_prefix("@sha256:"))
        .is_some_and(is_sha256)
}

fn validate_rendered_compose(bytes: &[u8], image_lock: &ImageLock) -> Result<(), LauncherError> {
    let root: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        LauncherError::new(
            "COMPOSE_RENDER_INVALID",
            "Docker Compose 未返回有效的渲染 JSON。",
        )
    })?;
    let services = root
        .get("services")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            LauncherError::new("COMPOSE_RENDER_INVALID", "渲染后的 Compose 缺少 services。")
        })?;
    let actual_services: BTreeSet<&str> = services.keys().map(String::as_str).collect();
    let expected_services: BTreeSet<&str> = EXPECTED_SERVICES.into_iter().collect();
    if actual_services != expected_services {
        return Err(LauncherError::new(
            "COMPOSE_SERVICE_SET_REJECTED",
            "渲染后的 Compose 服务集合与固定发布拓扑不一致。",
        ));
    }

    for service in EXPECTED_SERVICES {
        let definition = services
            .get(service)
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                LauncherError::new(
                    "COMPOSE_RENDER_INVALID",
                    "渲染后的 Compose service 不是对象。",
                )
            })?;
        let image = definition
            .get("image")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                LauncherError::new(
                    "COMPOSE_IMAGE_REJECTED",
                    "渲染后的 Compose service 缺少固定镜像。",
                )
            })?;
        if image_lock.for_service(service) != Some(image) {
            return Err(LauncherError::new(
                "COMPOSE_IMAGE_REJECTED",
                "渲染后的 Compose 镜像不匹配发布镜像锁。",
            ));
        }
        validate_rendered_service_secrets(service, definition.get("secrets"))?;
        validate_rendered_storage_contract(service, definition)?;
        validate_rendered_network_security(service, definition)?;

        let ports = definition.get("ports");
        if service == "web" {
            let ports = ports
                .and_then(serde_json::Value::as_array)
                .filter(|values| values.len() == 1)
                .ok_or_else(|| {
                    LauncherError::new("COMPOSE_PORT_REJECTED", "Web 必须且只能声明一个宿主端口。")
                })?;
            let port = ports[0].as_object().ok_or_else(|| {
                LauncherError::new("COMPOSE_PORT_REJECTED", "Web 端口声明格式无效。")
            })?;
            if json_port_number(port.get("target")) != Some(8080)
                || json_port_number(port.get("published")) != Some(17_860)
                || port.get("host_ip").and_then(serde_json::Value::as_str) != Some("127.0.0.1")
                || port.get("protocol").and_then(serde_json::Value::as_str) != Some("tcp")
            {
                return Err(LauncherError::new(
                    "COMPOSE_PORT_REJECTED",
                    "Web 端口必须精确绑定 127.0.0.1:17860 到容器 8080/tcp。",
                ));
            }
        } else if ports.is_some_and(|value| {
            !value.is_null() && value.as_array().is_none_or(|values| !values.is_empty())
        }) {
            return Err(LauncherError::new(
                "COMPOSE_PORT_REJECTED",
                "API、Worker、出口守卫、PostgreSQL 和迁移服务不得映射宿主端口。",
            ));
        }
    }
    Ok(())
}

fn validate_rendered_storage_contract(
    service: &str,
    definition: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), LauncherError> {
    let expected: &[(&str, &str)] = match service {
        "postgres" => &[("postgres-data", "/var/lib/postgresql/data")],
        "api" => &[("log-data", "/var/lib/datax-studio/logs")],
        "worker" => &[
            ("log-data", "/var/lib/datax-studio/logs"),
            ("workspace-data", "/var/lib/datax-studio/runs"),
        ],
        "migrate" | "egress-guard" | "web" => &[],
        _ => {
            return Err(LauncherError::new(
                "COMPOSE_STORAGE_CONTRACT_REJECTED",
                "未知服务不能获得运行数据卷。",
            ));
        }
    };
    let values: &[serde_json::Value] = match definition.get("volumes") {
        None | Some(serde_json::Value::Null) => &[],
        Some(serde_json::Value::Array(values)) => values.as_slice(),
        _ => {
            return Err(LauncherError::new(
                "COMPOSE_STORAGE_CONTRACT_REJECTED",
                "渲染后的 Compose volume 授权格式无效。",
            ));
        }
    };
    if values.len() != expected.len() {
        return Err(LauncherError::new(
            "COMPOSE_STORAGE_CONTRACT_REJECTED",
            "渲染后的 Compose volume 集合不符合固定持久化契约。",
        ));
    }
    let mut actual = BTreeSet::new();
    for value in values {
        let mount = value.as_object().ok_or_else(|| {
            LauncherError::new(
                "COMPOSE_STORAGE_CONTRACT_REJECTED",
                "渲染后的 Compose volume 条目不是对象。",
            )
        })?;
        let source = mount
            .get("source")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                LauncherError::new(
                    "COMPOSE_STORAGE_CONTRACT_REJECTED",
                    "渲染后的 Compose volume 缺少固定 source。",
                )
            })?;
        let target = mount
            .get("target")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                LauncherError::new(
                    "COMPOSE_STORAGE_CONTRACT_REJECTED",
                    "渲染后的 Compose volume 缺少固定 target。",
                )
            })?;
        if mount.get("type").and_then(serde_json::Value::as_str) != Some("volume")
            || mount
                .get("read_only")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            || mount
                .get("volume")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|options| !options.is_empty())
        {
            return Err(LauncherError::new(
                "COMPOSE_STORAGE_CONTRACT_REJECTED",
                "运行数据只能使用固定的可写 Docker named volume，不能改成 bind、只读或附加选项。",
            ));
        }
        if !actual.insert((source.to_owned(), target.to_owned())) {
            return Err(LauncherError::new(
                "COMPOSE_STORAGE_CONTRACT_REJECTED",
                "渲染后的 Compose volume 包含重复映射。",
            ));
        }
    }
    let expected: BTreeSet<(String, String)> = expected
        .iter()
        .map(|(source, target)| ((*source).to_owned(), (*target).to_owned()))
        .collect();
    if actual != expected {
        return Err(LauncherError::new(
            "COMPOSE_STORAGE_CONTRACT_REJECTED",
            "PostgreSQL、API 或 Worker 的数据卷 source/target 不符合固定持久化契约。",
        ));
    }

    if service == "worker"
        && definition
            .get("environment")
            .and_then(serde_json::Value::as_object)
            .and_then(|environment| environment.get("DES_WORKSPACE_VOLUME_PATH"))
            .and_then(serde_json::Value::as_str)
            != Some("/var/lib/datax-studio/runs")
    {
        return Err(LauncherError::new(
            "COMPOSE_STORAGE_CONTRACT_REJECTED",
            "Worker 工作目录必须精确指向 workspace-data 的固定容器挂载路径。",
        ));
    }
    Ok(())
}

fn validate_rendered_service_secrets(
    service: &str,
    value: Option<&serde_json::Value>,
) -> Result<(), LauncherError> {
    let expected: &[(&str, &str)] = match service {
        "api" => &[
            ("api_database_password", "database_password"),
            ("jwt_private_key", "jwt_private_key.pem"),
            ("jwt_public_key", "jwt_public_key.pem"),
            ("refresh_token_hmac_key", "refresh_token_hmac_key"),
            ("idempotency_hmac_key", "idempotency_hmac_key"),
            ("credential_kek_v1", "credential-kek-v1.key"),
            (
                "egress_lease_creation_capability",
                "egress_lease_creation_capability",
            ),
        ],
        "worker" => &[
            ("worker_database_password", "database_password"),
            ("idempotency_hmac_key", "idempotency_hmac_key"),
            ("credential_kek_v1", "credential-kek-v1.key"),
            (
                "egress_lease_creation_capability",
                "egress_lease_creation_capability",
            ),
        ],
        "postgres" => &[("postgres_password", "postgres_password")],
        "migrate" => &[
            ("postgres_password", "database_password"),
            (
                "egress_guard_database_password",
                "egress_guard_database_password",
            ),
            ("api_database_password", "api_database_password"),
            ("worker_database_password", "worker_database_password"),
        ],
        "egress-guard" => &[
            (
                "egress_guard_database_password",
                "egress_guard_database_password",
            ),
            (
                "egress_lease_creation_capability",
                "egress_lease_creation_capability",
            ),
        ],
        "web" => &[],
        _ => {
            return Err(LauncherError::new(
                "COMPOSE_SECRET_TARGET_REJECTED",
                "未知服务不能获得 secret。",
            ));
        }
    };
    let values: &[serde_json::Value] = match value {
        None | Some(serde_json::Value::Null) => &[],
        Some(serde_json::Value::Array(values)) => values.as_slice(),
        _ => {
            return Err(LauncherError::new(
                "COMPOSE_SECRET_TARGET_REJECTED",
                "渲染后的 Compose secret 授权格式无效。",
            ));
        }
    };
    if values.len() != expected.len() {
        return Err(LauncherError::new(
            "COMPOSE_SECRET_TARGET_REJECTED",
            "渲染后的 Compose secret 授权集合不符合固定服务契约。",
        ));
    }
    let mut actual = BTreeSet::new();
    for value in values {
        let (source, target) = match value {
            serde_json::Value::String(source) => (source.as_str(), source.as_str()),
            serde_json::Value::Object(secret) => {
                let source = secret
                    .get("source")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        LauncherError::new(
                            "COMPOSE_SECRET_TARGET_REJECTED",
                            "渲染后的 Compose secret 缺少 source。",
                        )
                    })?;
                let target = secret
                    .get("target")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(source);
                (source, target)
            }
            _ => {
                return Err(LauncherError::new(
                    "COMPOSE_SECRET_TARGET_REJECTED",
                    "渲染后的 Compose secret 条目格式无效。",
                ));
            }
        };
        let target = target
            .strip_prefix("/run/secrets/")
            .unwrap_or(target)
            .to_owned();
        if !actual.insert((source.to_owned(), target)) {
            return Err(LauncherError::new(
                "COMPOSE_SECRET_TARGET_REJECTED",
                "渲染后的 Compose secret 授权包含重复条目。",
            ));
        }
    }
    let expected: BTreeSet<(String, String)> = expected
        .iter()
        .map(|(source, target)| ((*source).to_owned(), (*target).to_owned()))
        .collect();
    if actual != expected {
        return Err(LauncherError::new(
            "COMPOSE_SECRET_TARGET_REJECTED",
            "渲染后的 Compose secret source/容器 target 不符合固定契约。",
        ));
    }
    Ok(())
}

fn validate_rendered_network_security(
    service: &str,
    definition: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), LauncherError> {
    let network_mode = definition
        .get("network_mode")
        .and_then(serde_json::Value::as_str);
    let networks = rendered_string_keys(definition.get("networks"), "COMPOSE_NETWORK_REJECTED")?;
    if matches!(service, "api" | "worker") {
        if network_mode != Some("service:egress-guard") || !networks.is_empty() {
            return Err(LauncherError::new(
                "COMPOSE_NETWORK_REJECTED",
                "API/Worker 必须且只能共享 egress-guard 的网络命名空间。",
            ));
        }
    } else if network_mode.is_some() || networks != BTreeSet::from([String::from("control")]) {
        return Err(LauncherError::new(
            "COMPOSE_NETWORK_REJECTED",
            "PostgreSQL、迁移、出口守卫与 Web 必须且只能加入 control 网络。",
        ));
    }

    let cap_add = rendered_string_values(definition.get("cap_add"), "COMPOSE_CAPABILITY_REJECTED")?;
    let cap_drop =
        rendered_string_values(definition.get("cap_drop"), "COMPOSE_CAPABILITY_REJECTED")?;
    if service == "egress-guard" {
        if cap_add != BTreeSet::from([String::from("NET_ADMIN")])
            || cap_drop != BTreeSet::from([String::from("ALL")])
            || definition
                .get("read_only")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            return Err(LauncherError::new(
                "COMPOSE_CAPABILITY_REJECTED",
                "只有 egress-guard 可获得 NET_ADMIN，且必须只读并先丢弃全部 capability。",
            ));
        }
    } else if !cap_add.is_empty()
        || (matches!(service, "api" | "worker" | "migrate")
            && cap_drop != BTreeSet::from([String::from("ALL")]))
    {
        return Err(LauncherError::new(
            "COMPOSE_CAPABILITY_REJECTED",
            "除 egress-guard 外不得增加 capability；API、Worker 与迁移服务必须 cap_drop=ALL。",
        ));
    }

    let environment = definition
        .get("environment")
        .and_then(serde_json::Value::as_object);
    if environment.is_some_and(|values| values.contains_key("DES_EGRESS_ENFORCEMENT_VERIFIED")) {
        return Err(LauncherError::new(
            "COMPOSE_EGRESS_CONTRACT_REJECTED",
            "不得使用可由环境变量伪造的出口执行已验证布尔值。",
        ));
    }
    if matches!(service, "api" | "worker" | "migrate") {
        let environment = environment.ok_or_else(|| {
            LauncherError::new(
                "COMPOSE_EGRESS_CONTRACT_REJECTED",
                "后端服务缺少固定出口执行契约。",
            )
        })?;
        for (name, expected) in [
            ("DES_EGRESS_POLICY_VERSION", "des-nftables-egress-v1"),
            ("DES_RESOLVER_POLICY_VERSION", "des-system-dns-v1"),
            (
                "DES_EGRESS_ATTESTATION_URL",
                "http://127.0.0.1:17990/v1/attestation",
            ),
        ] {
            if environment.get(name).and_then(serde_json::Value::as_str) != Some(expected) {
                return Err(LauncherError::new(
                    "COMPOSE_EGRESS_CONTRACT_REJECTED",
                    "后端服务的出口策略版本或 loopback 证明端点不符合固定契约。",
                ));
            }
        }
        let expected_database_user = match service {
            "api" => "datax_api",
            "worker" => "datax_worker",
            "migrate" => "datax_studio",
            _ => unreachable!(),
        };
        if environment
            .get("DES_DATABASE_USER")
            .and_then(serde_json::Value::as_str)
            != Some(expected_database_user)
            || environment
                .get("DES_DATABASE_PASSWORD_FILE")
                .and_then(serde_json::Value::as_str)
                != Some("/run/secrets/database_password")
        {
            return Err(LauncherError::new(
                "COMPOSE_DATABASE_ROLE_REJECTED",
                "迁移、API 与 Worker 必须使用各自固定数据库角色和通用容器内密码 target。",
            ));
        }
        let guard_secret_path = environment
            .get("DES_EGRESS_GUARD_DATABASE_PASSWORD_FILE")
            .and_then(serde_json::Value::as_str);
        if (service == "migrate")
            != (guard_secret_path == Some("/run/secrets/egress_guard_database_password"))
        {
            return Err(LauncherError::new(
                "COMPOSE_EGRESS_CONTRACT_REJECTED",
                "出口守卫数据库密码路径只能提供给一次性迁移服务。",
            ));
        }
        let lease_creation_capability_path = environment
            .get("DES_EGRESS_LEASE_CREATION_CAPABILITY_FILE")
            .and_then(serde_json::Value::as_str);
        let requires_lease_creation_capability = matches!(service, "api" | "worker");
        if (requires_lease_creation_capability
            && lease_creation_capability_path
                != Some("/run/secrets/egress_lease_creation_capability"))
            || (!requires_lease_creation_capability && lease_creation_capability_path.is_some())
        {
            return Err(LauncherError::new(
                "COMPOSE_EGRESS_CONTRACT_REJECTED",
                "出口租约创建能力路径只能以固定 target 提供给 API 和 Worker。",
            ));
        }
        for (name, expected) in [
            (
                "DES_API_DATABASE_PASSWORD_FILE",
                "/run/secrets/api_database_password",
            ),
            (
                "DES_WORKER_DATABASE_PASSWORD_FILE",
                "/run/secrets/worker_database_password",
            ),
        ] {
            let actual = environment.get(name).and_then(serde_json::Value::as_str);
            if (service == "migrate") != (actual == Some(expected)) {
                return Err(LauncherError::new(
                    "COMPOSE_DATABASE_ROLE_REJECTED",
                    "API/Worker 角色初始化密码路径只能提供给一次性迁移服务。",
                ));
            }
        }
    }
    if service == "postgres" {
        let environment = environment.ok_or_else(|| {
            LauncherError::new(
                "COMPOSE_DATABASE_ROLE_REJECTED",
                "PostgreSQL 缺少固定初始化角色环境。",
            )
        })?;
        if environment
            .get("POSTGRES_USER")
            .and_then(serde_json::Value::as_str)
            != Some("datax_studio")
            || environment
                .get("POSTGRES_DB")
                .and_then(serde_json::Value::as_str)
                != Some("datax_studio")
            || environment
                .get("POSTGRES_PASSWORD_FILE")
                .and_then(serde_json::Value::as_str)
                != Some("/run/secrets/postgres_password")
        {
            return Err(LauncherError::new(
                "COMPOSE_DATABASE_ROLE_REJECTED",
                "PostgreSQL 初始化所有者或密码 target 不符合固定契约。",
            ));
        }
    }

    if matches!(service, "api" | "worker")
        && rendered_dependency_condition(definition, "egress-guard") != Some("service_healthy")
    {
        return Err(LauncherError::new(
            "COMPOSE_EGRESS_CONTRACT_REJECTED",
            "API/Worker 必须等待 egress-guard 通过健康检查。",
        ));
    }
    if service == "egress-guard" {
        let health_test = definition
            .get("healthcheck")
            .and_then(serde_json::Value::as_object)
            .and_then(|healthcheck| healthcheck.get("test"))
            .and_then(serde_json::Value::as_array)
            .and_then(|values| {
                values
                    .iter()
                    .map(serde_json::Value::as_str)
                    .collect::<Option<Vec<_>>>()
            });
        if health_test
            != Some(vec![
                "CMD",
                "python3",
                "/opt/datax-egress-guard/healthcheck.py",
            ])
            || rendered_dependency_condition(definition, "migrate")
                != Some("service_completed_successfully")
        {
            return Err(LauncherError::new(
                "COMPOSE_EGRESS_CONTRACT_REJECTED",
                "egress-guard 必须等待迁移完成并使用固定的 loopback 证明健康检查。",
            ));
        }
    }
    Ok(())
}

fn rendered_dependency_condition<'a>(
    definition: &'a serde_json::Map<String, serde_json::Value>,
    dependency: &str,
) -> Option<&'a str> {
    definition
        .get("depends_on")?
        .as_object()?
        .get(dependency)?
        .as_object()?
        .get("condition")?
        .as_str()
}

fn rendered_string_keys(
    value: Option<&serde_json::Value>,
    error_code: &str,
) -> Result<BTreeSet<String>, LauncherError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(BTreeSet::new()),
        Some(serde_json::Value::Object(values)) => Ok(values.keys().cloned().collect()),
        _ => Err(LauncherError::new(
            error_code,
            "渲染后的 Compose 集合格式无效。",
        )),
    }
}

fn rendered_string_values(
    value: Option<&serde_json::Value>,
    error_code: &str,
) -> Result<BTreeSet<String>, LauncherError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(BTreeSet::new()),
        Some(serde_json::Value::Array(values)) => {
            let actual: BTreeSet<String> = values
                .iter()
                .map(|value| {
                    value.as_str().map(str::to_owned).ok_or_else(|| {
                        LauncherError::new(error_code, "渲染后的 Compose 字符串集合格式无效。")
                    })
                })
                .collect::<Result<_, _>>()?;
            if actual.len() != values.len() {
                return Err(LauncherError::new(
                    error_code,
                    "渲染后的 Compose 字符串集合包含重复值。",
                ));
            }
            Ok(actual)
        }
        _ => Err(LauncherError::new(
            error_code,
            "渲染后的 Compose 字符串集合格式无效。",
        )),
    }
}

fn json_port_number(value: Option<&serde_json::Value>) -> Option<u16> {
    match value? {
        serde_json::Value::Number(number) => number.as_u64()?.try_into().ok(),
        serde_json::Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn validate_actual_compose_ports(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
) -> Result<(), LauncherError> {
    let inventory = inspect_compose_project_inventory(tools, installation, image_lock)?;
    validate_actual_compose_ports_for_inventory(tools, start_tools, installation, &inventory)
}

fn validate_actual_compose_ports_for_runtime(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    image_lock: &ImageLock,
    active_runtime: &ActiveRuntimeSnapshot,
) -> Result<(), LauncherError> {
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let inventory = inspect_compose_project_inventory_for_runtime(
        tools,
        installation,
        image_lock,
        active_runtime,
    )?;
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    let result =
        validate_actual_compose_ports_for_inventory(tools, start_tools, installation, &inventory);
    require_active_runtime_snapshot_unchanged(installation, active_runtime)?;
    result
}

fn validate_actual_compose_ports_for_inventory(
    tools: &Tools,
    start_tools: &StartTools,
    installation: &Installation,
    inventory: &ComposeProjectInventory,
) -> Result<(), LauncherError> {
    require_authenticated_compose_services(inventory, &[], true)?;
    let ids = inventory.container_ids();

    let mut arguments = vec![
        OsString::from("inspect"),
        OsString::from("--format"),
        OsString::from(
            r#"{{ index .Config.Labels "com.docker.compose.service" }}|{{json .NetworkSettings.Ports}}"#,
        ),
    ];
    arguments.extend(ids.iter().map(|identifier| OsString::from(*identifier)));
    let docker_environment = tools.docker_environment();
    let inspected = run_process(
        &tools.docker,
        &arguments,
        &docker_environment,
        &installation.install_dir,
        PROCESS_TIMEOUT,
    )?;
    if !inspected.status.success() {
        return Err(LauncherError::new(
            "ACTUAL_PORT_CHECK_FAILED",
            "无法读取实际 Docker 端口绑定。",
        ));
    }

    let mut seen = BTreeSet::new();
    let mut binding_count = 0_usize;
    let inspected_text = normalize_text(&inspected.stdout);
    for line in inspected_text.lines() {
        let (service, ports) = line.split_once('|').ok_or_else(|| {
            LauncherError::new("ACTUAL_PORT_CHECK_FAILED", "Docker 端口绑定响应格式无效。")
        })?;
        if !EXPECTED_SERVICES.contains(&service) || !seen.insert(service.to_owned()) {
            return Err(LauncherError::new(
                "ACTUAL_CONTAINER_SET_REJECTED",
                "实际容器 service 标签缺失、重复或越界。",
            ));
        }
        let ports: serde_json::Value = serde_json::from_str(ports).map_err(|_| {
            LauncherError::new("ACTUAL_PORT_CHECK_FAILED", "Docker 端口绑定 JSON 无效。")
        })?;
        if ports.is_null() {
            continue;
        }
        let ports = ports.as_object().ok_or_else(|| {
            LauncherError::new("ACTUAL_PORT_CHECK_FAILED", "Docker 端口绑定不是对象。")
        })?;
        for (container_port, bindings) in ports {
            if bindings.is_null() {
                continue;
            }
            let bindings = bindings.as_array().ok_or_else(|| {
                LauncherError::new("ACTUAL_PORT_CHECK_FAILED", "Docker 宿主绑定不是数组。")
            })?;
            for binding in bindings {
                binding_count += 1;
                let binding = binding.as_object().ok_or_else(|| {
                    LauncherError::new("ACTUAL_PORT_CHECK_FAILED", "Docker 宿主绑定项无效。")
                })?;
                if service != "web"
                    || container_port != "8080/tcp"
                    || binding.get("HostIp").and_then(serde_json::Value::as_str)
                        != Some("127.0.0.1")
                    || binding.get("HostPort").and_then(serde_json::Value::as_str) != Some("17860")
                {
                    return Err(LauncherError::new(
                        "ACTUAL_PORT_REJECTED",
                        "检测到 loopback Web 以外的实际宿主端口，服务已停止。",
                    ));
                }
            }
        }
    }
    let expected: BTreeSet<String> = EXPECTED_SERVICES.into_iter().map(str::to_owned).collect();
    if seen != expected || binding_count != 1 {
        return Err(LauncherError::new(
            "ACTUAL_PORT_REJECTED",
            "实际端口映射必须且只能是 Web 127.0.0.1:17860。",
        ));
    }
    let listeners = host_port_listeners(start_tools, installation)?;
    if listeners != BTreeSet::from([String::from("127.0.0.1")]) {
        return Err(LauncherError::new(
            "ACTUAL_LISTENER_REJECTED",
            "实际 Windows IPv4/IPv6 监听必须且只能是 127.0.0.1:17860。",
        ));
    }
    Ok(())
}

fn run_process(
    program: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    working_directory: &Path,
    timeout: Duration,
) -> Result<ProcessOutput, LauncherError> {
    run_process_internal(
        program,
        arguments,
        environment,
        working_directory,
        timeout,
        None,
    )
}

fn run_process_with_secret_stdin(
    program: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    working_directory: &Path,
    timeout: Duration,
    secret_stdin: Zeroizing<Vec<u8>>,
) -> Result<ProcessOutput, LauncherError> {
    run_process_internal(
        program,
        arguments,
        environment,
        working_directory,
        timeout,
        Some(secret_stdin),
    )
}

fn run_process_to_new_file(
    program: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    working_directory: &Path,
    timeout: Duration,
    output: &Path,
) -> Result<ProcessOutput, LauncherError> {
    let output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|_| {
            LauncherError::new(
                "BACKUP_PG_DUMP_CREATE_FAILED",
                "无法以 create_new 创建 pg_dump staging 文件。",
            )
        })?;
    let mut command = controlled_child_command(
        program,
        arguments,
        environment,
        working_directory,
        Stdio::null(),
    );

    let mut child = command
        .spawn()
        .map_err(|_| LauncherError::new("PROCESS_START_FAILED", "无法启动所需的固定本机进程。"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| LauncherError::new("PROCESS_CAPTURE_FAILED", "无法捕获子进程标准输出。"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| LauncherError::new("PROCESS_CAPTURE_FAILED", "无法捕获子进程标准错误。"))?;
    let stdout_writer = thread::spawn(move || {
        let mut output_file = output_file;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = stdout.read(&mut buffer).map_err(|_| CaptureFailure::Read)?;
            if read == 0 {
                break;
            }
            output_file
                .write_all(&buffer[..read])
                .map_err(|_| CaptureFailure::Read)?;
        }
        output_file.flush().map_err(|_| CaptureFailure::Read)?;
        output_file.sync_all().map_err(|_| CaptureFailure::Read)
    });
    let stderr_reader = thread::spawn(move || read_bounded(stderr));

    let status = match child
        .wait_timeout(timeout)
        .map_err(|_| LauncherError::new("PROCESS_WAIT_FAILED", "等待本机子进程失败。"))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_writer.join();
            let _ = stderr_reader.join();
            return Err(LauncherError::new(
                "PROCESS_TIMEOUT",
                "本机依赖命令在限定时间内没有结束。",
            ));
        }
    };
    stdout_writer
        .join()
        .map_err(|_| LauncherError::new("PROCESS_CAPTURE_FAILED", "写入 pg_dump 输出失败。"))?
        .map_err(|failure| capture_failure("pg_dump 标准输出", failure))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| LauncherError::new("PROCESS_CAPTURE_FAILED", "读取子进程标准错误失败。"))?
        .map_err(|failure| capture_failure("标准错误", failure))?;
    Ok(ProcessOutput {
        status,
        stdout: Vec::new(),
        stderr,
    })
}

fn run_process_internal(
    program: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    working_directory: &Path,
    timeout: Duration,
    secret_stdin: Option<Zeroizing<Vec<u8>>>,
) -> Result<ProcessOutput, LauncherError> {
    let stdin = if secret_stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    };
    let mut command =
        controlled_child_command(program, arguments, environment, working_directory, stdin);

    let mut child = command
        .spawn()
        .map_err(|_| LauncherError::new("PROCESS_START_FAILED", "无法启动所需的固定本机进程。"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| LauncherError::new("PROCESS_CAPTURE_FAILED", "无法捕获子进程标准输出。"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| LauncherError::new("PROCESS_CAPTURE_FAILED", "无法捕获子进程标准错误。"))?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let stdin_writer = secret_stdin.map(|mut secret| {
        let mut stdin = child.stdin.take();
        thread::spawn(move || {
            let result = stdin
                .as_mut()
                .ok_or(())
                .and_then(|pipe| pipe.write_all(&secret).map_err(|_| ()))
                .and_then(|_| {
                    stdin
                        .as_mut()
                        .ok_or(())
                        .and_then(|pipe| pipe.flush().map_err(|_| ()))
                });
            secret.zeroize();
            result
        })
    });

    let status = match child
        .wait_timeout(timeout)
        .map_err(|_| LauncherError::new("PROCESS_WAIT_FAILED", "等待本机子进程失败。"))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            if let Some(writer) = stdin_writer {
                let _ = writer.join();
            }
            return Err(LauncherError::new(
                "PROCESS_TIMEOUT",
                "本机依赖命令在限定时间内没有结束。",
            ));
        }
    };
    let stdin_failed = match stdin_writer {
        Some(writer) => writer
            .join()
            .map_err(|_| {
                LauncherError::new(
                    "PROCESS_STDIN_FAILED",
                    "向受控子进程传递一次性标准输入失败。",
                )
            })?
            .is_err(),
        None => false,
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| LauncherError::new("PROCESS_CAPTURE_FAILED", "读取子进程标准输出失败。"))?
        .map_err(|failure| capture_failure("标准输出", failure))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| LauncherError::new("PROCESS_CAPTURE_FAILED", "读取子进程标准错误失败。"))?
        .map_err(|failure| capture_failure("标准错误", failure))?;
    if stdin_failed {
        return Err(LauncherError::new(
            "PROCESS_STDIN_FAILED",
            "向受控子进程传递一次性标准输入失败。",
        ));
    }
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
    })
}

fn controlled_child_command(
    program: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    working_directory: &Path,
    stdin: Stdio,
) -> Command {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(working_directory)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for &name in CHILD_ENVIRONMENT_REMOVALS {
        command.env_remove(name);
    }
    for (name, value) in environment {
        command.env(name, value);
    }
    command
}

fn capture_failure(stream: &str, failure: CaptureFailure) -> LauncherError {
    match failure {
        CaptureFailure::Read => LauncherError::new(
            "PROCESS_CAPTURE_FAILED",
            format!("读取子进程{stream}失败；Launcher 不会使用不完整输出作安全判断。"),
        ),
        CaptureFailure::Truncated => LauncherError::new(
            "PROCESS_OUTPUT_TRUNCATED",
            format!("子进程{stream}超过安全上限；Launcher 不会使用截断输出作安全判断。"),
        ),
    }
}

fn read_bounded<R: Read>(mut reader: R) -> Result<Vec<u8>, CaptureFailure> {
    let mut kept = Vec::with_capacity(COMMAND_OUTPUT_LIMIT.min(4096));
    let mut buffer = [0_u8; 4096];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Err(_) => return Err(CaptureFailure::Read),
            Ok(read) => {
                let remaining = COMMAND_OUTPUT_LIMIT.saturating_sub(kept.len());
                if read > remaining {
                    truncated = true;
                }
                kept.extend_from_slice(&buffer[..read.min(remaining)]);
            }
        }
    }
    if truncated {
        Err(CaptureFailure::Truncated)
    } else {
        Ok(kept)
    }
}

fn wait_for_http(path: &str, timeout: Duration, timeout_code: &str) -> Result<(), LauncherError> {
    let deadline = Instant::now() + timeout;
    let mut last = HttpProbe::Unreachable;
    while Instant::now() < deadline {
        last = probe_http(path, Duration::from_secs(2));
        if last == HttpProbe::Status(200) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(750));
    }
    match last {
        HttpProbe::Status(503) => Err(LauncherError::new(
            timeout_code,
            "服务持续返回 503：一个或多个关键组件未就绪。Launcher 不会打开浏览器或伪装成功。",
        )),
        HttpProbe::Status(status) => Err(LauncherError::new(
            timeout_code,
            format!("本机健康检查返回未预期的 HTTP {status}。"),
        )),
        HttpProbe::InvalidResponse => Err(LauncherError::new(
            timeout_code,
            "本机健康检查返回了无效 HTTP 响应。",
        )),
        HttpProbe::Unreachable => Err(LauncherError::new(
            timeout_code,
            "无法连接本机健康检查端点。",
        )),
    }
}

fn probe_http(path: &str, timeout: Duration) -> HttpProbe {
    if !matches!(path, LIVE_PATH | READY_PATH) {
        return HttpProbe::InvalidResponse;
    }
    let address = SocketAddr::from(([127, 0, 0, 1], 17_860));
    let mut stream = match TcpStream::connect_timeout(&address, timeout) {
        Ok(stream) => stream,
        Err(_) => return HttpProbe::Unreachable,
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:17860\r\nConnection: close\r\nUser-Agent: DataXEnterpriseStudioLauncher/1\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return HttpProbe::Unreachable;
    }
    let mut first_line = String::new();
    let mut reader = BufReader::new(stream).take(1024);
    if reader.read_line(&mut first_line).is_err() {
        return HttpProbe::InvalidResponse;
    }
    parse_http_status_line(&first_line)
        .map(HttpProbe::Status)
        .unwrap_or(HttpProbe::InvalidResponse)
}

fn host_port_listeners(
    tools: &StartTools,
    installation: &Installation,
) -> Result<BTreeSet<String>, LauncherError> {
    let output = run_process(
        &tools.netstat,
        &[
            OsString::from("-a"),
            OsString::from("-n"),
            OsString::from("-o"),
            OsString::from("-p"),
            OsString::from("tcp"),
        ],
        &[],
        &installation.install_dir,
        PROCESS_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(LauncherError::new(
            "HOST_LISTENER_CHECK_FAILED",
            "无法枚举 Windows IPv4/IPv6 TCP 监听。",
        ));
    }
    parse_netstat_listeners(&normalize_text(&output.stdout), 17_860)
}

fn parse_netstat_listeners(
    output: &str,
    target_port: u16,
) -> Result<BTreeSet<String>, LauncherError> {
    let mut listeners = BTreeSet::new();
    let port_suffix = format!(":{target_port}");
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5
            || !fields[0].eq_ignore_ascii_case("TCP")
            || !fields[3].eq_ignore_ascii_case("LISTENING")
            || !fields[1].ends_with(&port_suffix)
        {
            continue;
        }
        let address = if fields[1].starts_with('[') {
            let end = fields[1].find(']').ok_or_else(|| {
                LauncherError::new(
                    "HOST_LISTENER_RESPONSE_INVALID",
                    "Windows IPv6 监听格式无效。",
                )
            })?;
            if fields[1].get(end + 1..) != Some(port_suffix.as_str()) {
                return Err(LauncherError::new(
                    "HOST_LISTENER_RESPONSE_INVALID",
                    "Windows IPv6 监听端口格式无效。",
                ));
            }
            &fields[1][1..end]
        } else {
            fields[1]
                .strip_suffix(&port_suffix)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    LauncherError::new(
                        "HOST_LISTENER_RESPONSE_INVALID",
                        "Windows IPv4 监听格式无效。",
                    )
                })?
        };
        listeners.insert(address.to_ascii_lowercase());
    }
    Ok(listeners)
}

fn parse_http_status_line(value: &str) -> Option<u16> {
    let mut parts = value.trim_end_matches(['\r', '\n']).split_whitespace();
    let protocol = parts.next()?;
    if protocol != "HTTP/1.1" && protocol != "HTTP/1.0" {
        return None;
    }
    let status = parts.next()?;
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    status.parse().ok()
}

fn extract_sid(value: &str) -> Option<String> {
    let start = value.find("S-1-")?;
    let sid: String = value[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit() || matches!(*character, 'S' | '-'))
        .collect();
    let pieces: Vec<&str> = sid.split('-').collect();
    if pieces.len() < 4
        || pieces[0] != "S"
        || pieces[1] != "1"
        || pieces[2..]
            .iter()
            .any(|piece| piece.is_empty() || !piece.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some(sid)
}

fn normalize_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\0', "")
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn is_supported_host_signature(
    major: u32,
    build: u32,
    product_type: u8,
    native_machine: u16,
) -> bool {
    major == 10 && build >= 22_000 && product_type == 1 && native_machine == 0x8664
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_secret_bytes(value: &[u8]) -> bool {
    value.len() == 64
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn hex_lower_32(bytes: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = [0_u8; 64];
    for (index, byte) in bytes.iter().enumerate() {
        result[index * 2] = HEX[(byte >> 4) as usize];
        result[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    result
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn constant_time_ascii_equal(left: &str, right: &str) -> bool {
    constant_time_bytes_equal(left.as_bytes(), right.as_bytes())
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub(crate) fn signer_identity_allowed(actual: &str, allowed: &[String]) -> bool {
    allowed
        .iter()
        .any(|expected| constant_time_ascii_equal(actual, expected))
}

fn constant_time_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (*left ^ *right)
        })
        == 0
}

fn independent_hmac_keys_valid(refresh: &[u8], idempotency: &[u8]) -> bool {
    refresh.len() == 32
        && idempotency.len() == 32
        && !constant_time_bytes_equal(refresh, idempotency)
}

fn independent_database_passwords_valid(postgres: &[u8], guard: &[u8]) -> bool {
    independent_database_password_set_valid(&[postgres, guard])
}

fn independent_database_password_set_valid(passwords: &[&[u8]]) -> bool {
    passwords.len() >= 2
        && passwords
            .iter()
            .all(|password| password.len() == 64 && is_secret_bytes(password))
        && passwords.iter().enumerate().all(|(index, password)| {
            passwords
                .iter()
                .skip(index + 1)
                .all(|other| !constant_time_bytes_equal(password, other))
        })
}

fn independent_credential_kek_valid(
    credential_kek: &[u8],
    refresh: &[u8],
    idempotency: &[u8],
) -> bool {
    credential_kek.len() == 32
        && independent_hmac_keys_valid(refresh, idempotency)
        && !constant_time_bytes_equal(credential_kek, refresh)
        && !constant_time_bytes_equal(credential_kek, idempotency)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compose_inventory_test_image_lock() -> ImageLock {
        let digest = "b".repeat(64);
        ImageLock {
            postgres: format!("postgres@sha256:{digest}"),
            api: format!("ghcr.io/xiaoli2hust/datax-studio-api@sha256:{digest}"),
            egress_guard: format!("ghcr.io/xiaoli2hust/datax-studio-egress-guard@sha256:{digest}"),
            worker: format!("ghcr.io/xiaoli2hust/datax-studio-worker@sha256:{digest}"),
            web: format!("ghcr.io/xiaoli2hust/datax-studio-web@sha256:{digest}"),
        }
    }

    fn legacy_test_runtime_volume_names() -> RuntimeVolumeNames {
        RuntimeVolumeNames {
            postgres: String::from("des-postgres-data"),
            logs: String::from("des-log-data"),
            workspace: String::from("des-workspace-data"),
        }
    }

    #[test]
    fn release_image_availability_covers_each_locked_runtime_image_once() {
        let lock = compose_inventory_test_image_lock();
        let references = release_image_references(&lock);
        assert_eq!(references.len(), 5);
        assert_eq!(references.into_iter().collect::<BTreeSet<_>>().len(), 5);
        assert!(references.iter().all(|image| image.contains("@sha256:")));
        assert!(references.contains(&lock.worker.as_str()));
    }

    #[test]
    fn compose_start_refuses_implicit_pull_after_image_and_capacity_admission() {
        assert_eq!(COMPOSE_UP_WITHOUT_PULL, ["up", "--pull", "never", "-d"]);
    }

    fn compose_inventory_test_container(
        service: &str,
        identifier: char,
        image_lock: &ImageLock,
        volume_names: &RuntimeVolumeNames,
    ) -> InspectedComposeContainer {
        let expected = expected_runtime_volume_mounts(service, volume_names);
        InspectedComposeContainer {
            id: identifier.to_string().repeat(64),
            image: image_lock.for_service(service).unwrap().to_owned(),
            labels: BTreeMap::from([
                (
                    String::from(COMPOSE_PROJECT_LABEL),
                    String::from(COMPOSE_PROJECT),
                ),
                (String::from(COMPOSE_SERVICE_LABEL), String::from(service)),
            ]),
            mounts: expected
                .iter()
                .map(|(name, destination)| ComposeContainerMount {
                    kind: String::from("volume"),
                    name: Some((*name).to_owned()),
                    destination: (*destination).to_owned(),
                    read_write: true,
                })
                .collect(),
            running: true,
        }
    }

    #[test]
    fn compose_inventory_requires_exact_owned_service_set_images_and_runtime_mounts() {
        let lock = compose_inventory_test_image_lock();
        let volume_names = legacy_test_runtime_volume_names();
        let identifiers = ['a', 'b', 'c', 'd', 'e', 'f'];
        let containers = EXPECTED_SERVICES
            .iter()
            .zip(identifiers)
            .map(|(service, identifier)| {
                compose_inventory_test_container(service, identifier, &lock, &volume_names)
            })
            .collect();
        let inventory =
            validate_compose_project_inventory(containers, &lock, &volume_names).unwrap();
        assert!(inventory.is_complete());
        assert!(inventory.service_is_running("web"));
        assert_eq!(inventory.container_ids().len(), EXPECTED_SERVICES.len());
        assert!(
            require_authenticated_compose_services(&inventory, &["api", "worker"], true).is_ok()
        );

        let mut unknown_service =
            compose_inventory_test_container("api", 'a', &lock, &volume_names);
        unknown_service.labels.insert(
            String::from(COMPOSE_SERVICE_LABEL),
            String::from("attacker"),
        );
        let mut duplicate_service =
            compose_inventory_test_container("api", 'a', &lock, &volume_names);
        let duplicate_service_second =
            compose_inventory_test_container("api", 'b', &lock, &volume_names);
        let mut wrong_image = compose_inventory_test_container("api", 'a', &lock, &volume_names);
        wrong_image.image = lock.web.clone();
        let mut wrong_mount = compose_inventory_test_container("worker", 'a', &lock, &volume_names);
        wrong_mount.mounts.pop();
        let mut wrong_project = compose_inventory_test_container("api", 'a', &lock, &volume_names);
        wrong_project.labels.insert(
            String::from(COMPOSE_PROJECT_LABEL),
            String::from("other-project"),
        );

        for containers in [
            vec![unknown_service],
            vec![duplicate_service, duplicate_service_second],
            vec![wrong_image],
            vec![wrong_mount],
            vec![wrong_project],
        ] {
            assert_eq!(
                validate_compose_project_inventory(containers, &lock, &volume_names)
                    .unwrap_err()
                    .code(),
                "COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED"
            );
        }

        duplicate_service = compose_inventory_test_container("api", 'a', &lock, &volume_names);
        duplicate_service.mounts.push(ComposeContainerMount {
            kind: String::from("volume"),
            name: Some(String::from("unexpected")),
            destination: String::from("/unexpected"),
            read_write: true,
        });
        assert_eq!(
            validate_compose_project_inventory(vec![duplicate_service], &lock, &volume_names)
                .unwrap_err()
                .code(),
            "COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED"
        );
    }

    #[test]
    fn compose_inventory_uses_the_active_generations_opaque_volume_names() {
        let lock = compose_inventory_test_image_lock();
        let generation_id = "c".repeat(32);
        let active_names = RuntimeVolumeNames {
            postgres: format!("des-postgres-{generation_id}"),
            logs: format!("des-log-{generation_id}"),
            workspace: format!("des-workspace-{generation_id}"),
        };
        let identifiers = ['a', 'b', 'c', 'd', 'e', 'f'];
        let containers = EXPECTED_SERVICES
            .iter()
            .zip(identifiers)
            .map(|(service, identifier)| {
                compose_inventory_test_container(service, identifier, &lock, &active_names)
            })
            .collect();
        assert!(
            validate_compose_project_inventory(containers, &lock, &active_names)
                .unwrap()
                .is_complete()
        );

        let worker = compose_inventory_test_container("worker", 'a', &lock, &active_names);
        assert!(runtime_volume_mounts_match(
            "worker",
            &worker.mounts,
            &active_names,
        ));
        assert!(!runtime_volume_mounts_match(
            "worker",
            &worker.mounts,
            &legacy_test_runtime_volume_names(),
        ));
    }

    #[test]
    fn docker_storage_probe_uses_fixed_hardening_and_active_generation_volumes() {
        let generation_id = "d".repeat(32);
        let active_names = RuntimeVolumeNames {
            postgres: format!("des-postgres-{generation_id}"),
            logs: format!("des-log-{generation_id}"),
            workspace: format!("des-workspace-{generation_id}"),
        };
        let worker_image = format!(
            "ghcr.io/xiaoli2hust/datax-studio-worker@sha256:{}",
            "e".repeat(64)
        );
        let helper = helper_container_identity(
            DOCKER_STORAGE_PROBE_HELPER_ROLE,
            &[
                "installation-id",
                &active_names.postgres,
                &active_names.logs,
                &active_names.workspace,
            ],
        );
        let arguments = docker_storage_probe_arguments(&active_names, &worker_image, &helper)
            .unwrap()
            .iter()
            .map(|argument| argument.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();

        assert_eq!(arguments.first().map(String::as_str), Some("run"));
        for expected in [
            ["--pull=never", "--name"],
            ["--name", helper.name.as_str()],
            ["--network", "none"],
            ["--user", "0:0"],
            ["--cap-drop", "ALL"],
            ["--cap-add", "DAC_READ_SEARCH"],
            ["--security-opt", "no-new-privileges:true"],
            ["--pids-limit", "16"],
            ["--memory", "64m"],
            ["--cpus", "0.25"],
            ["--tmpfs", "/tmp:rw,noexec,nosuid,size=4m"],
            ["--entrypoint", "python"],
        ] {
            assert!(
                arguments
                    .windows(2)
                    .any(|pair| pair[0] == expected[0] && pair[1] == expected[1])
            );
        }
        assert!(arguments.iter().any(|argument| argument == "--rm"));
        assert!(arguments.iter().any(|argument| argument == "--read-only"));
        let capability_additions = arguments
            .windows(2)
            .filter_map(|pair| (pair[0] == "--cap-add").then_some(pair[1].as_str()))
            .collect::<Vec<_>>();
        let capability_drops = arguments
            .windows(2)
            .filter_map(|pair| (pair[0] == "--cap-drop").then_some(pair[1].as_str()))
            .collect::<Vec<_>>();
        assert_eq!(capability_additions, vec!["DAC_READ_SEARCH"]);
        assert_eq!(capability_drops, vec!["ALL"]);
        assert!(arguments.windows(2).any(|pair| {
            pair[0] == "--label"
                && pair[1] == format!("{HELPER_CONTAINER_ROLE_LABEL}={}", helper.role)
        }));
        assert!(arguments.windows(2).any(|pair| {
            pair[0] == "--label"
                && pair[1] == format!("{HELPER_CONTAINER_ID_LABEL}={}", helper.opaque_id)
        }));
        assert!(!arguments.iter().any(|argument| argument == "--privileged"));
        for forbidden in [
            "--env",
            "--env-file",
            "--secret",
            "--volume",
            "--device",
            "--pid",
            "--ipc",
            "--uts",
        ] {
            assert!(
                !arguments.iter().any(|argument| argument == forbidden),
                "capacity probe must not receive {forbidden}",
            );
        }
        assert!(
            !arguments
                .iter()
                .any(|argument| argument == "--pull=missing")
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("/run/secrets"))
        );

        let mounts = arguments
            .windows(2)
            .filter_map(|pair| (pair[0] == "--mount").then_some(pair[1].as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            mounts,
            vec![
                format!(
                    "type=volume,source=des-postgres-{generation_id},target=/probe/postgres-data,readonly,volume-nocopy"
                ),
                format!(
                    "type=volume,source=des-log-{generation_id},target=/probe/log-data,readonly,volume-nocopy"
                ),
                format!(
                    "type=volume,source=des-workspace-{generation_id},target=/probe/workspace-data,readonly,volume-nocopy"
                ),
            ]
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("des-postgres-data"))
        );
        assert_eq!(arguments[arguments.len() - 3], worker_image);
        assert_eq!(arguments[arguments.len() - 2], "-c");
        assert_eq!(
            arguments.last().map(String::as_str),
            Some(platform::DOCKER_STORAGE_PROBE_SCRIPT)
        );
    }

    #[test]
    fn runtime_volume_inspection_requires_exact_local_identity_without_options() {
        fn output(
            name: &str,
            driver: &str,
            options: &str,
            labels: BTreeMap<String, String>,
        ) -> Vec<u8> {
            format!(
                "{}\t{}\t{options}\t{}\n",
                serde_json::to_string(name).unwrap(),
                serde_json::to_string(driver).unwrap(),
                serde_json::to_string(&labels).unwrap(),
            )
            .into_bytes()
        }

        let labels = BTreeMap::from([
            (
                String::from(VOLUME_IDENTITY_LABEL),
                String::from("a").repeat(64),
            ),
            (
                String::from(VOLUME_ROLE_LABEL),
                String::from("postgres-data"),
            ),
        ]);
        let name = "des-postgres-data";
        let installation_id = "a".repeat(64);
        assert!(
            validate_runtime_volume_inspection(
                &output(name, "local", "null", labels.clone()),
                name,
                &installation_id,
                "postgres-data",
            )
            .is_ok()
        );
        assert!(
            validate_runtime_volume_inspection(
                &output(name, "local", "{}", labels.clone()),
                name,
                &installation_id,
                "postgres-data",
            )
            .is_ok()
        );

        let mut wrong_labels = labels.clone();
        wrong_labels.insert(String::from(VOLUME_ROLE_LABEL), String::from("log-data"));
        for inspected in [
            output("other", "local", "null", labels.clone()),
            output(name, "nfs", "null", labels.clone()),
            output(name, "local", r#"{"type":"nfs"}"#, labels.clone()),
            output(name, "local", "null", wrong_labels),
            b"not-json\n".to_vec(),
        ] {
            assert_eq!(
                validate_runtime_volume_inspection(
                    &inspected,
                    name,
                    &installation_id,
                    "postgres-data",
                )
                .unwrap_err()
                .code(),
                "RUNTIME_VOLUME_IDENTITY_MISMATCH"
            );
        }
    }

    #[test]
    fn compose_inventory_parsers_reject_ambiguous_or_malformed_docker_output() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        assert_eq!(
            parse_compose_project_container_ids(format!("{first}\n{second}\n").as_bytes()).unwrap(),
            vec![first.clone(), second.clone()]
        );
        for output in [
            format!("{first}\n{first}\n"),
            format!("{}\n", "A".repeat(64)),
            String::from("not-a-container\n"),
        ] {
            assert_eq!(
                parse_compose_project_container_ids(output.as_bytes())
                    .unwrap_err()
                    .code(),
                "COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED"
            );
        }

        let lock = compose_inventory_test_image_lock();
        let volume_names = legacy_test_runtime_volume_names();
        let container = compose_inventory_test_container("api", 'a', &lock, &volume_names);
        let encoded = format!(
            "{}\t{}\t{}\t{}\t{}\n",
            serde_json::to_string(&container.id).unwrap(),
            serde_json::to_string(&container.image).unwrap(),
            serde_json::to_string(&container.labels).unwrap(),
            serde_json::to_string(&container.mounts).unwrap(),
            serde_json::to_string(&container.running).unwrap(),
        );
        assert_eq!(
            parse_compose_project_container_inspections(
                encoded.as_bytes(),
                std::slice::from_ref(&container.id),
            )
            .unwrap(),
            vec![container.clone()]
        );
        assert_eq!(
            parse_compose_project_container_inspections(
                format!("{encoded}extra\n").as_bytes(),
                &[container.id],
            )
            .unwrap_err()
            .code(),
            "COMPOSE_PROJECT_OWNERSHIP_UNVERIFIED"
        );
    }

    #[test]
    fn cli_defaults_to_start() {
        assert_eq!(parse_action(Vec::<OsString>::new()).unwrap(), Action::Start);
    }

    #[test]
    fn cli_requires_force_to_follow_stop() {
        assert_eq!(
            parse_action([OsString::from("stop"), OsString::from("--force")]).unwrap(),
            Action::Stop { force: true }
        );
        assert_eq!(
            parse_action([OsString::from("--force")])
                .unwrap_err()
                .code(),
            "INVALID_ARGUMENTS"
        );
    }

    #[test]
    fn cli_accepts_only_complete_backup_argument_set() {
        let expected = Action::Backup {
            data_output: PathBuf::from(r"C:\backup\data"),
            secrets_output: PathBuf::from(r"D:\backup\keys"),
            data_key: PathBuf::from(r"C:\input\data.key"),
            secrets_key: PathBuf::from(r"D:\input\secrets.key"),
        };
        assert_eq!(
            parse_action([
                OsString::from("backup"),
                OsString::from("--data-output"),
                OsString::from(r"C:\backup\data"),
                OsString::from("--secrets-output"),
                OsString::from(r"D:\backup\keys"),
                OsString::from("--data-key"),
                OsString::from(r"C:\input\data.key"),
                OsString::from("--secrets-key"),
                OsString::from(r"D:\input\secrets.key"),
            ])
            .unwrap(),
            expected,
        );
        assert_eq!(
            parse_action([
                OsString::from("backup"),
                OsString::from("--data-output"),
                OsString::from(r"C:\backup\data"),
            ])
            .unwrap_err()
            .code(),
            "INVALID_ARGUMENTS",
        );
    }

    #[test]
    fn cli_accepts_restore_only_as_complete_fail_closed_request() {
        let expected = Action::Restore {
            data_input: PathBuf::from(r"C:\backup\data.dxdata"),
            secrets_input: PathBuf::from(r"D:\backup\keys.dxkeys"),
            data_key: PathBuf::from(r"C:\input\data.key"),
            secrets_key: PathBuf::from(r"D:\input\secrets.key"),
        };
        assert_eq!(
            parse_action([
                OsString::from("restore"),
                OsString::from("--data-input"),
                OsString::from(r"C:\backup\data.dxdata"),
                OsString::from("--secrets-input"),
                OsString::from(r"D:\backup\keys.dxkeys"),
                OsString::from("--data-key"),
                OsString::from(r"C:\input\data.key"),
                OsString::from("--secrets-key"),
                OsString::from(r"D:\input\secrets.key"),
            ])
            .unwrap(),
            expected,
        );
        assert_eq!(
            parse_action([
                OsString::from("restore"),
                OsString::from("--data-input"),
                OsString::from(r"C:\backup\data.dxdata"),
            ])
            .unwrap_err()
            .code(),
            "INVALID_ARGUMENTS",
        );
    }

    #[test]
    fn backup_helper_command_is_networkless_and_never_mounts_workspace() {
        let helper = helper_container_identity(BACKUP_DATA_HELPER_ROLE, &["installation", "sid"]);
        let arguments = backup_container_arguments(
            "ghcr.io/xiaoli2hust/datax-studio-worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[OsString::from(
                "type=volume,source=des-log-data,target=/backup/logs,readonly,volume-nocopy",
            )],
            &helper,
        );
        let text = arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("--network\nnone"));
        assert!(text.contains("--pull=never"));
        assert!(text.contains(&format!("--name\n{}", helper.name)));
        assert!(text.contains(&format!(
            "{HELPER_CONTAINER_ROLE_LABEL}={BACKUP_DATA_HELPER_ROLE}"
        )));
        assert!(text.contains(&format!("{HELPER_CONTAINER_ID_LABEL}={}", helper.opaque_id)));
        assert!(text.contains("--read-only"));
        assert!(text.contains("--cap-drop\nALL"));
        assert!(text.contains("source=des-log-data"));
        assert!(!text.contains("workspace"));
        assert!(!text.contains("des-postgres-data"));
    }

    #[test]
    fn backup_mount_and_helper_identity_bind_the_active_generation() {
        fn prepared(generation_id: char) -> PreparedBackup {
            let generation_id = generation_id.to_string().repeat(32);
            let active_runtime = ActiveRuntimeSnapshot::from_generation(
                Path::new("/datax-app"),
                RuntimeGeneration::fresh(
                    generation_id.clone(),
                    "b".repeat(64),
                    "2026-08-02T02:30:00Z".to_owned(),
                )
                .unwrap(),
            )
            .unwrap();
            PreparedBackup {
                data_output: PathBuf::from("/backup/data"),
                secrets_output: PathBuf::from("/backup/secrets"),
                data_key: Zeroizing::new(vec![b'a'; 64]),
                secrets_key: Zeroizing::new(vec![b'b'; 64]),
                installation_id: active_runtime.generation.installation_id.clone(),
                active_runtime,
                current_user_sid: String::from("S-1-5-21-test"),
            }
        }

        let first = prepared('a');
        let second = prepared('c');
        assert_eq!(
            backup_log_volume_mount(&first),
            OsString::from(
                "type=volume,source=des-log-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,target=/backup/logs,readonly,volume-nocopy"
            )
        );
        let first_environment = first
            .active_runtime
            .compose_environment(Path::new("/datax-app"));
        let second_environment = second
            .active_runtime
            .compose_environment(Path::new("/datax-app"));
        assert!(first_environment.contains(&(
            OsString::from("DES_POSTGRES_VOLUME_NAME"),
            OsString::from("des-postgres-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )));
        assert_ne!(first_environment, second_environment);
        assert_ne!(
            backup_helper_container(BACKUP_DATA_HELPER_ROLE, &first).name,
            backup_helper_container(BACKUP_DATA_HELPER_ROLE, &second).name
        );
    }

    #[test]
    fn standard_backup_dump_excludes_the_complete_private_phase_a_schema() {
        let arguments = postgres_dump_arguments()
            .into_iter()
            .map(|value| value.into_string().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            vec![
                "exec",
                "-T",
                "postgres",
                "pg_dump",
                "--format=custom",
                "--compress=0",
                "--no-owner",
                "--no-privileges",
                "--serializable-deferrable",
                "--exclude-schema=des_phase_a_qualification",
                "--username=datax_studio",
                "--dbname=datax_studio",
            ]
        );
        assert!(arguments.contains(&format!(
            "--exclude-schema={BACKUP_EXCLUDED_PHASE_A_QUALIFICATION_SCHEMA}"
        )));
        assert!(
            !arguments
                .iter()
                .any(|value| value.starts_with("--exclude-table"))
        );
    }

    #[test]
    fn backup_result_requires_exact_kind_filename_and_digest_shape() {
        let valid = SystemBackupResult {
            schema_version: String::from("1.0"),
            code: String::from("BACKUP_CREATED"),
            kind: String::from("DATA"),
            backup_id: "a".repeat(32),
            filename: format!("{}.dxdata", "a".repeat(32)),
            package_bytes: 1,
            package_sha256: "b".repeat(64),
        };
        assert!(system_backup_result_valid(&valid, "DATA", ".dxdata"));
        let wrong_kind = SystemBackupResult {
            kind: String::from("SECRETS"),
            ..valid
        };
        assert!(!system_backup_result_valid(&wrong_kind, "DATA", ".dxdata",));
    }

    #[test]
    fn backup_password_is_only_a_single_stdin_line() {
        let stdin = backup_password_stdin(
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_eq!(stdin.len(), 65);
        assert_eq!(stdin.last(), Some(&b'\n'));
        assert_eq!(stdin.iter().filter(|byte| **byte == b'\n').count(), 1);
    }

    #[test]
    fn restore_passwords_are_exactly_two_separate_stdin_lines() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let secrets = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let stdin = restore_password_pair_stdin(data, secrets);
        assert_eq!(stdin.len(), 130);
        assert_eq!(stdin.iter().filter(|byte| **byte == b'\n').count(), 2);
        assert_eq!(&stdin[..64], data);
        assert_eq!(&stdin[65..129], secrets);
        assert_eq!(stdin[64], b'\n');
        assert_eq!(stdin[129], b'\n');
    }

    #[test]
    fn restore_stage_response_requires_non_success_gate_and_exact_ids() {
        let mut result = RestoreStageResult {
            schema_version: "1.0".to_owned(),
            code: "RESTORE_STAGED_COMMIT_BLOCKED".to_owned(),
            journal_id: "a".repeat(32),
            state: "STAGED_COMMIT_BLOCKED".to_owned(),
            data_backup_id: "b".repeat(32),
            secrets_backup_id: "c".repeat(32),
            installation_id: "d".repeat(64),
            next_required_gate: "PG_RESTORE_NEW_EMPTY_VOLUME_AND_ATOMIC_COMMIT".to_owned(),
        };
        assert!(restore_stage_result_valid(&result));
        result.state = "SUCCEEDED".to_owned();
        assert!(!restore_stage_result_valid(&result));
    }

    #[test]
    fn staged_restore_blocks_start_without_initialization_side_effects() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let app_data_root = env::temp_dir().join(format!(
            "datax-restore-start-guard-test-{}-{unique}",
            std::process::id()
        ));
        let restore_root = app_data_root.join("system-restore");
        let staging_root = restore_root.join("staging");
        let journal_directory = restore_root.join("journal");
        fs::create_dir_all(staging_root.join("data")).unwrap();
        fs::create_dir_all(staging_root.join("secrets")).unwrap();
        fs::create_dir_all(&journal_directory).unwrap();
        let journal_path = journal_directory.join("restore.json");
        let journal = br#"{"schema_version":"1.0","state":"STAGED_COMMIT_BLOCKED","authentication":{"algorithm":"HMAC-SHA256","key_domain":"DXES-RESTORE-JOURNAL-HMAC-v1","mac_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
        fs::write(&journal_path, journal).unwrap();

        let error = ensure_no_restore_in_progress(&app_data_root).unwrap_err();

        assert_eq!(error.code(), "RESTORE_IN_PROGRESS");
        assert!(error.to_string().contains("普通启动和备份"));
        assert_eq!(fs::read(&journal_path).unwrap(), journal);
        for path in [
            app_data_root.join("initialization-incomplete"),
            app_data_root.join("installation-id"),
            app_data_root.join("runtime-generation.json"),
            app_data_root.join("secrets"),
        ] {
            assert!(!path.exists(), "guard created {}", path.display());
        }
        assert!(staging_root.join("data").is_dir());
        assert!(staging_root.join("secrets").is_dir());

        fs::remove_dir_all(app_data_root).unwrap();
    }

    #[test]
    fn start_restore_guard_checks_only_the_fixed_restore_root_without_creating_it() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let app_data_root = env::temp_dir().join(format!(
            "datax-restore-start-guard-absence-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&app_data_root).unwrap();
        fs::create_dir(app_data_root.join("system-restore-old")).unwrap();

        ensure_no_restore_in_progress(&app_data_root).unwrap();

        assert!(!app_data_root.join("system-restore").exists());
        fs::remove_dir_all(app_data_root).unwrap();
    }

    #[test]
    fn restore_clean_target_recognizes_fixed_random_and_labeled_volume_names() {
        assert!(is_product_volume_name("des-postgres-data"));
        assert!(is_product_volume_name(&format!(
            "des-workspace-{}",
            "a".repeat(32)
        )));
        assert!(!is_product_volume_name("des-workspace-a"));
        assert!(!is_product_volume_name("unrelated-volume"));
    }

    #[test]
    fn restore_stage_container_is_named_networkless_and_bounded() {
        let helper = helper_container_identity(RESTORE_STAGE_HELPER_ROLE, &["sid", "restore"]);
        let arguments = restore_stage_container_arguments(
            "worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[OsString::from(
                "type=bind,source=C:\\backup\\data.dxdata,target=/restore/input/data.dxdata,readonly",
            )],
            &helper,
        );
        let text = arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("--network\nnone"));
        assert!(text.contains("--pull=never"));
        assert!(text.contains(&format!("--name\n{}", helper.name)));
        assert_eq!(
            arguments.iter().filter(|value| *value == "--name").count(),
            1
        );
        assert!(!text.contains("--name\ndes-restore-stage\n"));
        assert!(text.contains(&format!(
            "{HELPER_CONTAINER_ROLE_LABEL}={RESTORE_STAGE_HELPER_ROLE}"
        )));
        assert!(text.contains(&format!("{HELPER_CONTAINER_ID_LABEL}={}", helper.opaque_id)));
        assert!(text.contains("com.xiaoli.datax.restore-role=stage-pair"));
        assert!(text.contains("--read-only"));
        assert!(text.contains("--cap-drop\nALL"));
        assert!(text.contains("/restore/input/data.dxdata,readonly"));
        let name_index = arguments
            .iter()
            .position(|value| value == "--name")
            .unwrap();
        let entrypoint_index = arguments
            .iter()
            .position(|value| value == "--entrypoint")
            .unwrap();
        assert!(name_index < entrypoint_index);
    }

    #[test]
    fn helper_container_names_are_opaque_deterministic_and_installation_scoped() {
        let first =
            helper_container_identity(BACKUP_DATA_HELPER_ROLE, &["installation-a", "sid-a"]);
        let repeated =
            helper_container_identity(BACKUP_DATA_HELPER_ROLE, &["installation-a", "sid-a"]);
        let different =
            helper_container_identity(BACKUP_DATA_HELPER_ROLE, &["installation-b", "sid-a"]);
        assert_eq!(first, repeated);
        assert_ne!(first.name, different.name);
        assert!(first.name.starts_with("des-backup-data-"));
        assert_eq!(first.opaque_id.len(), 32);
        assert!(is_lower_hex_string(&first.opaque_id, 32));
        assert!(!first.name.contains("installation-a"));
    }

    #[test]
    fn helper_cleanup_accepts_only_one_lower_hex_container_id() {
        assert_eq!(
            parse_helper_container_id(b"abcdef012345\n").unwrap(),
            Some(String::from("abcdef012345"))
        );
        assert_eq!(parse_helper_container_id(b"\r\n").unwrap(), None);
        for output in [
            b"ABCDEF012345\n".as_slice(),
            b"abcdef012345\n123456abcdef\n",
        ] {
            assert_eq!(
                parse_helper_container_id(output).unwrap_err().code(),
                "HELPER_CLEANUP_IDENTITY_INVALID"
            );
        }
    }

    #[test]
    fn backup_keys_cannot_reuse_runtime_secret_material() {
        let database_password = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let raw_key = [0xab_u8; 32];
        let mut encoded_key = hex_lower_32(&raw_key);
        assert!(backup_key_conflicts_with_runtime_secret(
            database_password,
            database_password,
        ));
        assert!(backup_key_conflicts_with_runtime_secret(
            &encoded_key,
            &raw_key,
        ));
        encoded_key[0] = b'0';
        assert!(!backup_key_conflicts_with_runtime_secret(
            &encoded_key,
            &raw_key,
        ));
        encoded_key.zeroize();
    }

    #[test]
    fn cli_accepts_only_complete_internal_release_verification_command() {
        let installer = PathBuf::from(r"C:\candidate\Setup.exe");
        assert_eq!(
            parse_action([
                OsString::from("verify-release"),
                OsString::from("--installer"),
                installer.clone().into_os_string(),
            ])
            .unwrap(),
            Action::VerifyRelease { installer }
        );
        assert_eq!(
            parse_action([
                OsString::from("verify-release"),
                OsString::from("--installer"),
            ])
            .unwrap_err()
            .code(),
            "INVALID_ARGUMENTS"
        );
        assert_eq!(
            parse_action([
                OsString::from("verify-release"),
                OsString::from("--installer"),
                OsString::new(),
            ])
            .unwrap_err()
            .code(),
            "INVALID_ARGUMENTS"
        );
    }

    fn release_manifest_json(signers: serde_json::Value) -> Vec<u8> {
        serde_json::json!({
            "schema_version": "1.1",
            "product_version": env!("CARGO_PKG_VERSION"),
            "compose_sha256": "1".repeat(64),
            "images_sha256": "2".repeat(64),
            "acl_script_sha256": "3".repeat(64),
            "allowed_authenticode_signer_certificate_sha256": signers,
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn release_manifest_accepts_canonical_signer_rotation_set() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let parsed =
            parse_release_manifest(&release_manifest_json(serde_json::json!([first, second])))
                .unwrap();
        assert_eq!(
            parsed.allowed_authenticode_signer_certificate_sha256,
            vec!["a".repeat(64), "b".repeat(64)]
        );
    }

    #[test]
    fn release_manifest_rejects_missing_empty_or_malformed_signer_set() {
        let mut missing: serde_json::Value =
            serde_json::from_slice(&release_manifest_json(serde_json::json!(["a".repeat(64)])))
                .unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("allowed_authenticode_signer_certificate_sha256");
        assert_eq!(
            parse_release_manifest(missing.to_string().as_bytes())
                .unwrap_err()
                .code(),
            "RELEASE_MANIFEST_INVALID"
        );
        for signers in [
            serde_json::json!([]),
            serde_json::json!(["A".repeat(64)]),
            serde_json::json!(["a".repeat(63)]),
            serde_json::json!([
                "0".repeat(64),
                "1".repeat(64),
                "2".repeat(64),
                "3".repeat(64),
                "4".repeat(64),
                "5".repeat(64),
                "6".repeat(64),
                "7".repeat(64),
                "8".repeat(64),
            ]),
        ] {
            assert_eq!(
                parse_release_manifest(&release_manifest_json(signers))
                    .unwrap_err()
                    .code(),
                "RELEASE_MANIFEST_INVALID"
            );
        }
    }

    #[test]
    fn release_manifest_rejects_duplicate_or_unsorted_signer_set() {
        for signers in [
            serde_json::json!(["a".repeat(64), "a".repeat(64)]),
            serde_json::json!(["b".repeat(64), "a".repeat(64)]),
        ] {
            assert_eq!(
                parse_release_manifest(&release_manifest_json(signers))
                    .unwrap_err()
                    .code(),
                "RELEASE_MANIFEST_INVALID"
            );
        }
    }

    #[test]
    fn signer_identity_requires_exact_allowlist_membership() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let allowed = vec![first.clone(), second.clone()];
        assert!(signer_identity_allowed(&first, &allowed));
        assert!(signer_identity_allowed(&second, &allowed));
        assert!(!signer_identity_allowed(&"c".repeat(64), &allowed));
        assert!(!signer_identity_allowed(&first.to_uppercase(), &allowed));
    }

    #[test]
    fn active_attempts_have_distinct_exit_code() {
        assert_eq!(
            process_exit_code(&LauncherError::new("ACTIVE_ATTEMPTS_PRESENT", "blocked")),
            3
        );
        assert_eq!(
            process_exit_code(&LauncherError::new("DOCKER_DESKTOP_MISSING", "missing")),
            1
        );
    }

    #[test]
    fn parses_only_valid_http_status_lines() {
        assert_eq!(parse_http_status_line("HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(
            parse_http_status_line("HTTP/1.1 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(parse_http_status_line("ICY 200 OK\r\n"), None);
        assert_eq!(parse_http_status_line("HTTP/1.1 20 OK\r\n"), None);
    }

    #[test]
    fn enumerates_ipv4_and_ipv6_netstat_listeners() {
        let output = "\
  TCP    127.0.0.1:17860      0.0.0.0:0      LISTENING       101\n\
  TCP    0.0.0.0:17860        0.0.0.0:0      LISTENING       102\n\
  TCP    [::]:17860           [::]:0         LISTENING       103\n\
  TCP    [::1]:17860          [::]:0         LISTENING       104\n\
  TCP    127.0.0.1:443        0.0.0.0:0      LISTENING       105\n";
        assert_eq!(
            parse_netstat_listeners(output, 17_860).unwrap(),
            BTreeSet::from([
                String::from("0.0.0.0"),
                String::from("127.0.0.1"),
                String::from("::"),
                String::from("::1"),
            ])
        );
    }

    #[test]
    fn extracts_sid_without_localized_column_names() {
        assert_eq!(
            extract_sid("\"DESKTOP\\\\alice\",\"S-1-5-21-100-200-300-1001\"\r\n"),
            Some(String::from("S-1-5-21-100-200-300-1001"))
        );
        assert_eq!(extract_sid("no sid"), None);
    }

    #[test]
    fn parses_safe_and_blocked_lifecycle_results() {
        let safe: StopPreflight = serde_json::from_str(
            r#"{"safe_to_stop":true,"code":"SAFE_TO_STOP","active_execution_count":0,"active_probe_count":0}"#,
        )
        .unwrap();
        assert!(safe.safe_to_stop);

        let blocked: StopPreflight = serde_json::from_str(
            r#"{"safe_to_stop":false,"code":"ACTIVE_ATTEMPTS_PRESENT","active_execution_count":2,"active_probe_count":1}"#,
        )
        .unwrap();
        assert!(!blocked.safe_to_stop);
        assert_eq!(blocked.active_execution_count, 2);
        assert_eq!(blocked.active_probe_count, 1);
    }

    #[test]
    fn parses_only_allowlisted_digest_image_lock() {
        let digest = "a".repeat(64);
        let lock = format!(
            "DES_POSTGRES_IMAGE=postgres@sha256:{digest}\n\
             DES_API_IMAGE=ghcr.io/xiaoli2hust/datax-studio-api@sha256:{digest}\n\
             DES_EGRESS_GUARD_IMAGE=ghcr.io/xiaoli2hust/datax-studio-egress-guard@sha256:{digest}\n\
             DES_WORKER_IMAGE=ghcr.io/xiaoli2hust/datax-studio-worker@sha256:{digest}\n\
             DES_WEB_IMAGE=ghcr.io/xiaoli2hust/datax-studio-web@sha256:{digest}\n"
        );
        let parsed = parse_image_lock(lock.as_bytes()).unwrap();
        assert_eq!(parsed.postgres, format!("postgres@sha256:{digest}"));
        assert!(parse_image_lock(lock.replace("@sha256:", ":latest@sha256:").as_bytes()).is_err());
        assert!(
            parse_image_lock(
                lock.replace(
                    "ghcr.io/xiaoli2hust/datax-studio-web",
                    "example.invalid/datax-studio-web"
                )
                .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn validates_rendered_compose_images_secret_targets_and_loopback_port() {
        let digest = "b".repeat(64);
        let lock = ImageLock {
            postgres: format!("postgres@sha256:{digest}"),
            api: format!("ghcr.io/xiaoli2hust/datax-studio-api@sha256:{digest}"),
            egress_guard: format!("ghcr.io/xiaoli2hust/datax-studio-egress-guard@sha256:{digest}"),
            worker: format!("ghcr.io/xiaoli2hust/datax-studio-worker@sha256:{digest}"),
            web: format!("ghcr.io/xiaoli2hust/datax-studio-web@sha256:{digest}"),
        };
        let rendered = serde_json::json!({
            "services": {
                "postgres": {
                    "image": lock.postgres,
                    "secrets": ["postgres_password"],
                    "environment": {
                        "POSTGRES_DB": "datax_studio",
                        "POSTGRES_USER": "datax_studio",
                        "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres_password"
                    },
                    "volumes": [{
                        "type": "volume",
                        "source": "postgres-data",
                        "target": "/var/lib/postgresql/data",
                        "volume": {}
                    }],
                    "networks": {"control": null}
                },
                "migrate": {
                    "image": lock.api,
                    "secrets": [
                        {"source": "postgres_password", "target": "database_password"},
                        "egress_guard_database_password",
                        "api_database_password",
                        "worker_database_password"
                    ],
                    "cap_drop": ["ALL"],
                    "environment": {
                        "DES_EGRESS_POLICY_VERSION": "des-nftables-egress-v1",
                        "DES_RESOLVER_POLICY_VERSION": "des-system-dns-v1",
                        "DES_EGRESS_ATTESTATION_URL": "http://127.0.0.1:17990/v1/attestation",
                        "DES_EGRESS_GUARD_DATABASE_PASSWORD_FILE": "/run/secrets/egress_guard_database_password",
                        "DES_API_DATABASE_PASSWORD_FILE": "/run/secrets/api_database_password",
                        "DES_WORKER_DATABASE_PASSWORD_FILE": "/run/secrets/worker_database_password",
                        "DES_DATABASE_USER": "datax_studio",
                        "DES_DATABASE_PASSWORD_FILE": "/run/secrets/database_password"
                    },
                    "networks": {"control": null}
                },
                "egress-guard": {
                    "image": lock.egress_guard,
                    "secrets": [
                        "egress_guard_database_password",
                        "egress_lease_creation_capability"
                    ],
                    "cap_drop": ["ALL"],
                    "cap_add": ["NET_ADMIN"],
                    "read_only": true,
                    "depends_on": {
                        "migrate": {"condition": "service_completed_successfully"}
                    },
                    "healthcheck": {
                        "test": ["CMD", "python3", "/opt/datax-egress-guard/healthcheck.py"]
                    },
                    "networks": {"control": null}
                },
                "api": {
                    "image": lock.api,
                    "secrets": [
                        {"source": "api_database_password", "target": "database_password"},
                        {"source": "jwt_private_key", "target": "jwt_private_key.pem"},
                        {"source": "jwt_public_key", "target": "/run/secrets/jwt_public_key.pem"},
                        "refresh_token_hmac_key",
                        "idempotency_hmac_key",
                        {"source": "credential_kek_v1", "target": "credential-kek-v1.key"},
                        "egress_lease_creation_capability"
                    ],
                    "volumes": [{
                        "type": "volume",
                        "source": "log-data",
                        "target": "/var/lib/datax-studio/logs",
                        "volume": {}
                    }],
                    "cap_drop": ["ALL"],
                    "depends_on": {
                        "egress-guard": {"condition": "service_healthy"}
                    },
                    "environment": {
                        "DES_EGRESS_POLICY_VERSION": "des-nftables-egress-v1",
                        "DES_RESOLVER_POLICY_VERSION": "des-system-dns-v1",
                        "DES_EGRESS_ATTESTATION_URL": "http://127.0.0.1:17990/v1/attestation",
                        "DES_EGRESS_LEASE_CREATION_CAPABILITY_FILE": "/run/secrets/egress_lease_creation_capability",
                        "DES_DATABASE_USER": "datax_api",
                        "DES_DATABASE_PASSWORD_FILE": "/run/secrets/database_password"
                    },
                    "network_mode": "service:egress-guard"
                },
                "worker": {
                    "image": lock.worker,
                    "secrets": [
                        {"source": "worker_database_password", "target": "database_password"},
                        "idempotency_hmac_key",
                        {"source": "credential_kek_v1", "target": "/run/secrets/credential-kek-v1.key"},
                        "egress_lease_creation_capability"
                    ],
                    "cap_drop": ["ALL"],
                    "depends_on": {
                        "egress-guard": {"condition": "service_healthy"}
                    },
                    "environment": {
                        "DES_EGRESS_POLICY_VERSION": "des-nftables-egress-v1",
                        "DES_RESOLVER_POLICY_VERSION": "des-system-dns-v1",
                        "DES_EGRESS_ATTESTATION_URL": "http://127.0.0.1:17990/v1/attestation",
                        "DES_EGRESS_LEASE_CREATION_CAPABILITY_FILE": "/run/secrets/egress_lease_creation_capability",
                        "DES_DATABASE_USER": "datax_worker",
                        "DES_DATABASE_PASSWORD_FILE": "/run/secrets/database_password",
                        "DES_WORKSPACE_VOLUME_PATH": "/var/lib/datax-studio/runs"
                    },
                    "volumes": [
                        {
                            "type": "volume",
                            "source": "log-data",
                            "target": "/var/lib/datax-studio/logs",
                            "volume": {}
                        },
                        {
                            "type": "volume",
                            "source": "workspace-data",
                            "target": "/var/lib/datax-studio/runs",
                            "volume": {}
                        }
                    ],
                    "network_mode": "service:egress-guard"
                },
                "web": {
                    "image": lock.web,
                    "ports": [{
                        "target": 8080,
                        "published": "17860",
                        "host_ip": "127.0.0.1",
                        "protocol": "tcp"
                    }],
                    "networks": {"control": null}
                }
            }
        });
        assert!(validate_rendered_compose(rendered.to_string().as_bytes(), &lock).is_ok());

        let mut short_pem = rendered.clone();
        short_pem["services"]["api"]["secrets"][1] =
            serde_json::Value::String(String::from("jwt_private_key"));
        assert!(validate_rendered_compose(short_pem.to_string().as_bytes(), &lock).is_err());

        let mut separate_namespace = rendered.clone();
        separate_namespace["services"]["worker"]["network_mode"] =
            serde_json::Value::String(String::from("bridge"));
        assert!(
            validate_rendered_compose(separate_namespace.to_string().as_bytes(), &lock).is_err()
        );

        let mut privileged_api = rendered.clone();
        privileged_api["services"]["api"]["cap_add"] = serde_json::json!(["NET_ADMIN"]);
        assert!(validate_rendered_compose(privileged_api.to_string().as_bytes(), &lock).is_err());

        let mut forged_boolean = rendered.clone();
        forged_boolean["services"]["api"]["environment"]["DES_EGRESS_ENFORCEMENT_VERIFIED"] =
            serde_json::Value::String(String::from("true"));
        assert!(validate_rendered_compose(forged_boolean.to_string().as_bytes(), &lock).is_err());

        let mut wrong_capability_target = rendered.clone();
        wrong_capability_target["services"]["worker"]["environment"]["DES_EGRESS_LEASE_CREATION_CAPABILITY_FILE"] =
            serde_json::Value::String(String::from("/run/secrets/not-the-capability"));
        assert!(
            validate_rendered_compose(wrong_capability_target.to_string().as_bytes(), &lock)
                .is_err()
        );

        let mut wrong_workspace_path = rendered.clone();
        wrong_workspace_path["services"]["worker"]["environment"]["DES_WORKSPACE_VOLUME_PATH"] =
            serde_json::Value::String(String::from("/var/lib/datax-studio/workspaces"));
        assert!(
            validate_rendered_compose(wrong_workspace_path.to_string().as_bytes(), &lock).is_err()
        );

        let mut worker_extra_volume = rendered.clone();
        worker_extra_volume["services"]["worker"]["volumes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "type": "volume",
                "source": "postgres-data",
                "target": "/var/lib/datax-studio/unexpected",
                "volume": {}
            }));
        assert!(
            validate_rendered_compose(worker_extra_volume.to_string().as_bytes(), &lock).is_err()
        );

        let mut api_workspace_volume = rendered.clone();
        api_workspace_volume["services"]["api"]["volumes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "type": "volume",
                "source": "workspace-data",
                "target": "/var/lib/datax-studio/runs",
                "volume": {}
            }));
        assert!(
            validate_rendered_compose(api_workspace_volume.to_string().as_bytes(), &lock).is_err()
        );

        let mut wrong_postgres_target = rendered.clone();
        wrong_postgres_target["services"]["postgres"]["volumes"][0]["target"] =
            serde_json::Value::String(String::from("/var/lib/postgresql/other"));
        assert!(
            validate_rendered_compose(wrong_postgres_target.to_string().as_bytes(), &lock).is_err()
        );

        let mut owner_secret_in_api = rendered.clone();
        owner_secret_in_api["services"]["api"]["secrets"][0]["source"] =
            serde_json::Value::String(String::from("postgres_password"));
        assert!(
            validate_rendered_compose(owner_secret_in_api.to_string().as_bytes(), &lock).is_err()
        );

        let mut worker_uses_api_role = rendered.clone();
        worker_uses_api_role["services"]["worker"]["environment"]["DES_DATABASE_USER"] =
            serde_json::Value::String(String::from("datax_api"));
        assert!(
            validate_rendered_compose(worker_uses_api_role.to_string().as_bytes(), &lock).is_err()
        );

        let mut public = rendered;
        public["services"]["web"]["ports"][0]["host_ip"] =
            serde_json::Value::String(String::from("0.0.0.0"));
        assert!(validate_rendered_compose(public.to_string().as_bytes(), &lock).is_err());
    }

    #[test]
    fn validates_network_namespace_identifier_shape() {
        assert!(is_network_namespace_id("net:[4026532001]"));
        assert!(!is_network_namespace_id("net:[]"));
        assert!(!is_network_namespace_id("net:[4026532001]\\n"));
        assert!(!is_network_namespace_id("/proc/1/ns/net"));
    }

    #[test]
    fn extracts_only_registry_string_values() {
        assert_eq!(
            extract_registry_string(
                "\r\n    InstallPath    REG_SZ    C:\\Program Files\\Docker\\Docker\r\n",
                "InstallPath"
            ),
            Some(String::from(r"C:\Program Files\Docker\Docker"))
        );
        assert_eq!(
            extract_registry_string(
                "    InstallPath    REG_EXPAND_SZ    %ProgramFiles%\\Docker\r\n",
                "InstallPath"
            ),
            None
        );
    }

    #[test]
    fn wsl_status_and_local_docker_engine_gates_are_fail_closed_without_default_version() {
        // A missing or `1` DefaultVersion must not be an input here: it only controls newly
        // installed WSL distributions. The launcher separately verifies the live local engine.
        assert!(require_wsl_status(true).is_ok());
        assert_eq!(
            require_wsl_status(false).unwrap_err().code(),
            "WSL2_REQUIRED"
        );

        assert!(docker_reports_linux_amd64(true, b"linux|amd64\r\n"));
        assert!(!docker_reports_linux_amd64(true, b"linux|arm64\n"));
        assert!(!docker_reports_linux_amd64(false, b"linux|amd64\n"));

        assert!(docker_reports_desktop_linux(
            true,
            b"Docker Desktop|linux|x86_64\r\n"
        ));
        assert!(!docker_reports_desktop_linux(
            true,
            b"Docker Desktop|windows|amd64\n"
        ));
        assert!(!docker_reports_desktop_linux(
            false,
            b"Docker Desktop|linux|x86_64\n"
        ));
    }

    #[test]
    fn validates_lowercase_sha256() {
        assert!(is_sha256(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_sha256(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        ));
        assert!(!is_sha256("abc"));
    }

    #[test]
    fn validates_secret_without_accepting_newlines() {
        assert!(is_secret_bytes(
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_secret_bytes(
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\n"
        ));
    }

    #[test]
    fn rejects_server_and_windows_on_arm_signatures() {
        assert!(is_supported_host_signature(10, 22_000, 1, 0x8664));
        assert!(!is_supported_host_signature(10, 26_000, 3, 0x8664));
        assert!(!is_supported_host_signature(10, 26_000, 1, 0xaa64));
        assert!(!is_supported_host_signature(10, 19_045, 1, 0x8664));
    }

    #[test]
    fn hex_encoding_is_stable() {
        assert_eq!(hex_lower(&[0x00, 0x1f, 0xa5, 0xff]), "001fa5ff");
        assert_eq!(
            hex_lower_32(&[0xab; 32]),
            *b"abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn runtime_generation_timestamp_uses_strict_utc_calendar_time() {
        assert_eq!(
            current_utc_timestamp(UNIX_EPOCH + Duration::from_secs(946_684_800)).unwrap(),
            "2000-01-01T00:00:00Z"
        );
        assert_eq!(
            current_utc_timestamp(UNIX_EPOCH + Duration::from_secs(1_775_203_199)).unwrap(),
            "2026-04-03T07:59:59Z"
        );
        assert_eq!(
            current_utc_timestamp(UNIX_EPOCH).unwrap_err().code(),
            "RUNTIME_GENERATION_TIME_INVALID"
        );
    }

    #[test]
    fn runtime_generation_commit_never_overwrites_existing_pointer() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "datax-runtime-generation-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let pending = root.join("first.pending");
        let pointer = root.join("runtime-generation.json");
        fs::write(&pending, b"first").unwrap();
        platform::move_new_write_through(&pending, &pointer).unwrap();
        assert_eq!(fs::read(&pointer).unwrap(), b"first");
        assert!(!pending.exists());

        let second = root.join("second.pending");
        fs::write(&second, b"second").unwrap();
        assert_eq!(
            platform::move_new_write_through(&second, &pointer)
                .unwrap_err()
                .code(),
            "RUNTIME_GENERATION_ALREADY_EXISTS"
        );
        assert_eq!(fs::read(&pointer).unwrap(), b"first");
        assert_eq!(fs::read(&second).unwrap(), b"second");

        fs::remove_file(second).unwrap();
        fs::remove_file(pointer).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn runtime_generation_reader_rejects_symlink_pointer() {
        use std::os::unix::fs::symlink;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "datax-runtime-generation-symlink-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let target = root.join("attacker.json");
        let pointer = root.join("runtime-generation.json");
        let generation = RuntimeGeneration::legacy(
            "a".repeat(32),
            "b".repeat(64),
            "2026-08-01T09:30:00Z".to_owned(),
        )
        .unwrap();
        fs::write(&target, generation.to_bytes().unwrap()).unwrap();
        assert_eq!(read_runtime_generation(&target).unwrap(), generation);
        symlink(&target, &pointer).unwrap();

        assert_eq!(
            read_runtime_generation(&pointer).unwrap_err().code(),
            "RUNTIME_GENERATION_INVALID"
        );

        fs::remove_file(pointer).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn active_runtime_snapshot_derives_all_runtime_identity_from_one_fresh_pointer() {
        let generation_id = "a".repeat(32);
        let installation_id = "b".repeat(64);
        let generation = RuntimeGeneration::fresh(
            generation_id.clone(),
            installation_id.clone(),
            "2026-08-02T02:30:00Z".to_owned(),
        )
        .unwrap();
        let root = Path::new("/datax-app");
        let snapshot = ActiveRuntimeSnapshot::from_generation(root, generation.clone()).unwrap();

        assert_eq!(snapshot.generation, generation);
        assert_eq!(
            snapshot.secrets.directory,
            root.join(format!("generations/{generation_id}/secrets"))
        );
        assert_eq!(
            snapshot.secrets.postgres,
            root.join(format!(
                "generations/{generation_id}/secrets/postgres_password.txt"
            ))
        );
        assert_eq!(
            snapshot.volumes.postgres,
            format!("des-postgres-{generation_id}")
        );
        assert_eq!(snapshot.volumes.logs, format!("des-log-{generation_id}"));
        assert_eq!(
            snapshot.volumes.workspace,
            format!("des-workspace-{generation_id}")
        );
        assert_eq!(snapshot.volume_contract().installation_id, installation_id);
        assert!(snapshot.compose_environment(root).contains(&(
            OsString::from("DES_SECRET_DIR"),
            snapshot.secrets.directory.clone().into(),
        )));
    }

    #[test]
    fn fixed_string_comparison_checks_full_length() {
        assert!(constant_time_ascii_equal("abc", "abc"));
        assert!(!constant_time_ascii_equal("abc", "abd"));
        assert!(!constant_time_ascii_equal("abc", "ab"));
    }

    #[test]
    fn hmac_domains_require_distinct_exact_32_byte_keys() {
        assert!(independent_hmac_keys_valid(&[0x11; 32], &[0x22; 32]));
        assert!(!independent_hmac_keys_valid(&[0x11; 32], &[0x11; 32]));
        assert!(!independent_hmac_keys_valid(&[0x11; 31], &[0x22; 32]));
        assert!(!independent_hmac_keys_valid(&[0x11; 32], &[0x22; 33]));
    }

    #[test]
    fn database_passwords_require_distinct_lowercase_hex_values() {
        let first = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let second = b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let third = b"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let fourth = b"2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let fifth = b"3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(independent_database_passwords_valid(first, second));
        assert!(independent_database_password_set_valid(&[
            first, second, third, fourth, fifth
        ]));
        assert!(!independent_database_passwords_valid(first, first));
        assert!(!independent_database_password_set_valid(&[
            first, second, third, fourth, fourth
        ]));
        assert!(!independent_database_passwords_valid(
            first,
            b"ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ));
    }

    #[test]
    fn credential_kek_requires_exact_independent_key_material() {
        assert!(independent_credential_kek_valid(
            &[0x33; 32],
            &[0x11; 32],
            &[0x22; 32],
        ));
        assert!(!independent_credential_kek_valid(
            &[0x11; 32],
            &[0x11; 32],
            &[0x22; 32],
        ));
        assert!(!independent_credential_kek_valid(
            &[0x33; 31],
            &[0x11; 32],
            &[0x22; 32],
        ));
    }

    #[test]
    fn storage_identity_requires_three_volumes_and_marker_as_one_set() {
        assert_eq!(
            storage_identity_decision([false; 3], false, false),
            StorageIdentityDecision::Fresh,
        );
        assert_eq!(
            storage_identity_decision([true; 3], true, true),
            StorageIdentityDecision::Existing,
        );
        assert_eq!(
            storage_identity_decision([true, false, true], true, true),
            StorageIdentityDecision::IncompleteVolumes,
        );
        assert_eq!(
            storage_identity_decision([false; 3], true, true),
            StorageIdentityDecision::IdentityLost,
        );
        assert_eq!(
            storage_identity_decision([false; 3], false, true),
            StorageIdentityDecision::IdentityLost,
        );
        assert_eq!(
            storage_identity_decision([true; 3], false, false),
            StorageIdentityDecision::MarkerMissing,
        );
    }

    #[test]
    fn incomplete_initialization_recovers_only_before_any_runtime_use() {
        assert_eq!(RUNTIME_SECRET_COUNT, 10);
        assert_eq!(
            initialization_recovery_decision([false; 3], false, 0),
            InitializationRecoveryDecision::RegenerateSecrets,
        );
        assert_eq!(
            initialization_recovery_decision([false; 3], false, RUNTIME_SECRET_COUNT),
            InitializationRecoveryDecision::RegenerateSecrets,
        );
        assert_eq!(
            initialization_recovery_decision([true, false, false], false, RUNTIME_SECRET_COUNT,),
            InitializationRecoveryDecision::CompleteVolumes,
        );
        assert_eq!(
            initialization_recovery_decision([true; 3], false, RUNTIME_SECRET_COUNT),
            InitializationRecoveryDecision::CompleteVolumes,
        );
        assert_eq!(
            initialization_recovery_decision([true; 3], true, RUNTIME_SECRET_COUNT),
            InitializationRecoveryDecision::Finalize,
        );
        for unsafe_state in [
            initialization_recovery_decision([false; 3], true, RUNTIME_SECRET_COUNT),
            initialization_recovery_decision([true, false, false], false, RUNTIME_SECRET_COUNT - 1),
            initialization_recovery_decision([true, false, false], true, RUNTIME_SECRET_COUNT),
            initialization_recovery_decision([true; 3], true, RUNTIME_SECRET_COUNT - 1),
            initialization_recovery_decision([false; 3], false, RUNTIME_SECRET_COUNT + 1),
        ] {
            assert_eq!(unsafe_state, InitializationRecoveryDecision::Unsafe);
        }
    }

    #[test]
    fn bounded_process_output_fails_closed_on_truncation_or_read_error() {
        let oversized = vec![b'x'; COMMAND_OUTPUT_LIMIT + 1];
        assert_eq!(
            read_bounded(oversized.as_slice()),
            Err(CaptureFailure::Truncated)
        );

        struct FailingReader {
            first_read: bool,
        }

        impl Read for FailingReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.first_read {
                    return Err(std::io::Error::other("synthetic read failure"));
                }
                self.first_read = true;
                buffer[..3].copy_from_slice(b"abc");
                Ok(3)
            }
        }

        assert_eq!(
            read_bounded(FailingReader { first_read: false }),
            Err(CaptureFailure::Read)
        );
    }

    #[test]
    fn bootstrap_protocol_rejects_contradictory_exit_and_json() {
        let required = BootstrapStatus {
            required: Some(true),
            code: String::from("BOOTSTRAP_REQUIRED"),
        };
        assert_eq!(
            interpret_bootstrap_status_response(Some(0), &required).unwrap(),
            BootstrapState::Required
        );
        assert!(interpret_bootstrap_status_response(Some(3), &required).is_err());

        let created = BootstrapCreateResult {
            created: true,
            code: String::from("BOOTSTRAP_ADMIN_CREATED"),
        };
        assert_eq!(
            interpret_bootstrap_create_response(Some(0), &created).unwrap(),
            BootstrapCreateState::Created
        );
        assert!(interpret_bootstrap_create_response(Some(4), &created).is_err());
    }

    #[test]
    fn bootstrap_json_contract_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<BootstrapStatus>(
                r#"{"required":true,"code":"BOOTSTRAP_REQUIRED","extra":1}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<BootstrapCreateResult>(
                r#"{"created":true,"code":"BOOTSTRAP_ADMIN_CREATED","password":"leak"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn bootstrap_password_is_one_utf8_stdin_line_and_source_is_cleared() {
        let password = "安全-Temporary-密码-123!";
        let mut input = BootstrapInput {
            email: String::from("admin@example.com"),
            display_name: String::from("Admin"),
            password_utf16: Zeroizing::new(password.encode_utf16().collect()),
        };
        let encoded = encode_bootstrap_password(&mut input).unwrap();
        assert_eq!(encoded.as_slice(), format!("{password}\n").as_bytes());
        assert!(
            input.password_utf16.is_empty() || input.password_utf16.iter().all(|value| *value == 0)
        );
        assert!(!encoded[..encoded.len() - 1].contains(&b'\n'));
    }

    #[test]
    fn bootstrap_identity_and_password_validation_fail_closed() {
        let mut identity = BootstrapInput {
            email: String::from("  admin@example.com  "),
            display_name: String::from("  Local Admin  "),
            password_utf16: Zeroizing::new("Temporary-Password-123!".encode_utf16().collect()),
        };
        validate_bootstrap_identity(&mut identity).unwrap();
        assert_eq!(identity.email, "admin@example.com");
        assert_eq!(identity.display_name, "Local Admin");

        identity.password_utf16 =
            Zeroizing::new("Temporary\nPassword-123!".encode_utf16().collect());
        assert_eq!(
            encode_bootstrap_password(&mut identity).unwrap_err().code(),
            "BOOTSTRAP_PASSWORD_INVALID"
        );
        assert!(
            identity.password_utf16.is_empty()
                || identity.password_utf16.iter().all(|value| *value == 0)
        );
    }

    #[test]
    fn ed25519_pem_formats_round_trip_and_keys_match() {
        let signing = SigningKey::from_bytes(&[0x5a; 32]);
        let private_pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap();
        let public_pem = signing
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let decoded_private = SigningKey::from_pkcs8_pem(private_pem.as_str()).unwrap();
        let decoded_public = VerifyingKey::from_public_key_pem(&public_pem).unwrap();
        assert_eq!(decoded_private.verifying_key(), decoded_public);
        let private_key_marker = ["-----BEGIN ", "PRIVATE KEY-----\n"].concat();
        assert!(private_pem.starts_with(&private_key_marker));
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    }

    #[test]
    fn isolated_docker_cli_config_rejects_credentials_and_extra_state() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "datax-isolated-docker-config-test-{}-{unique}",
            std::process::id()
        ));
        let directory = root.join(DOCKER_CLI_CONFIG_DIRECTORY_NAME);
        let config = directory.join(DOCKER_CLI_CONFIG_FILE_NAME);
        fs::create_dir_all(&directory).unwrap();
        fs::write(&config, EMPTY_DOCKER_CLI_CONFIG).unwrap();
        assert!(validate_isolated_docker_cli_config(&directory, &config).is_ok());

        fs::write(&config, br#"{"auths":{},"credsStore":"unexpected"}"#).unwrap();
        assert_eq!(
            validate_isolated_docker_cli_config(&directory, &config)
                .unwrap_err()
                .code(),
            "DOCKER_CONFIG_INVALID"
        );

        fs::write(&config, EMPTY_DOCKER_CLI_CONFIG).unwrap();
        fs::write(directory.join("credential-helper-state"), b"unexpected").unwrap();
        assert_eq!(
            validate_isolated_docker_cli_config(&directory, &config)
                .unwrap_err()
                .code(),
            "DOCKER_CONFIG_INVALID"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn docker_child_environment_overrides_user_config_and_all_ambient_controls() {
        let isolated_config = PathBuf::from(r"C:\DataX\docker-cli-config");
        let tools = Tools {
            docker: PathBuf::from("docker.exe"),
            compose: PathBuf::from("docker-compose.exe"),
            docker_host: Some(OsString::from(LOCAL_DOCKER_DESKTOP_ENDPOINTS[0])),
            docker_cli_config_dir: isolated_config.clone(),
            reg: PathBuf::from("reg.exe"),
        };
        let command = controlled_child_command(
            Path::new("fixed-child.exe"),
            &[],
            &tools.docker_environment(),
            Path::new("."),
            Stdio::null(),
        );
        let values: BTreeMap<String, Option<String>> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            values.get("DOCKER_CONFIG"),
            Some(&Some(isolated_config.to_string_lossy().into_owned()))
        );
        assert_eq!(
            values.get("DOCKER_HOST"),
            Some(&Some(String::from(LOCAL_DOCKER_DESKTOP_ENDPOINTS[0])))
        );
        for &forbidden in CHILD_ENVIRONMENT_REMOVALS {
            if matches!(forbidden, "DOCKER_CONFIG" | "DOCKER_HOST") {
                continue;
            }
            let configured_removal = {
                #[cfg(windows)]
                {
                    // Windows environment variable names are case-insensitive. `Command`
                    // therefore represents HTTP_PROXY/http_proxy as one entry, even though
                    // either removal controls the inherited variable at process launch.
                    values.get(forbidden).or_else(|| {
                        values.iter().find_map(|(name, value)| {
                            name.eq_ignore_ascii_case(forbidden).then_some(value)
                        })
                    })
                }
                #[cfg(not(windows))]
                {
                    values.get(forbidden)
                }
            };
            assert_eq!(configured_removal, Some(&None), "{forbidden}");
        }
    }

    #[test]
    fn unhealthy_start_cleanup_failure_is_never_reported_as_clean() {
        let primary = LauncherError::new("API_LIVE_TIMEOUT", "synthetic primary failure");
        assert_eq!(
            merge_unhealthy_start_cleanup_result(primary.clone(), Ok(())).code(),
            "API_LIVE_TIMEOUT"
        );
        let error = merge_unhealthy_start_cleanup_result(
            primary,
            Err(LauncherError::new(
                "COMPOSE_START_CLEANUP_FAILED",
                "synthetic cleanup failure",
            )),
        );
        assert_eq!(error.code(), "STARTUP_CLEANUP_FAILED");
        assert!(error.message().contains("API_LIVE_TIMEOUT"));
        assert!(error.message().contains("COMPOSE_START_CLEANUP_FAILED"));
    }

    #[test]
    fn helper_cleanup_failure_is_never_reported_as_helper_success() {
        let helper = helper_container_identity(BACKUP_DATA_HELPER_ROLE, &["installation", "sid"]);
        let error = merge_helper_cleanup_result(
            LauncherError::new("PROCESS_TIMEOUT", "synthetic helper timeout"),
            &helper,
            Err(LauncherError::new(
                "HELPER_CLEANUP_REMOVE_FAILED",
                "synthetic cleanup failure",
            )),
        );
        assert_eq!(error.code(), "HELPER_CLEANUP_FAILED");
        assert!(error.message().contains("PROCESS_TIMEOUT"));
        assert!(error.message().contains("HELPER_CLEANUP_REMOVE_FAILED"));
    }
}
