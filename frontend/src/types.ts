export type Role = "ADMIN" | "DEVELOPER" | "OPERATOR" | "VIEWER";
export type ProjectRole = Exclude<Role, "ADMIN">;

export interface FieldError {
  path?: string;
  field?: string;
  code?: string;
  message: string;
}

export interface Problem {
  type: string;
  title: string;
  status: number;
  code: string;
  detail: string | null;
  instance: string;
  request_id: string | null;
  retryable: boolean;
  field_errors: FieldError[];
  details?: Record<string, unknown> | null;
}

export type HealthStatus = "UP" | "DOWN" | "DEGRADED";

export interface ComponentHealth {
  status: HealthStatus;
  code: string;
}

export interface HealthResponse {
  status: HealthStatus;
  version: string;
  checked_at: string;
  components: Record<string, ComponentHealth>;
}

export interface UserSummary {
  id: string;
  email: string;
  display_name: string;
  must_change_password: boolean;
}

export interface ScopedRoles {
  scope_type: "ORGANIZATION" | "PROJECT";
  scope_id: string;
  roles: Role[];
}

export interface AuthResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  user: UserSummary;
}

export interface MeResponse {
  user: UserSummary;
  role_assignments: ScopedRoles[];
}

export interface User extends UserSummary {
  status: "ACTIVE" | "LOCKED" | "DISABLED";
  role_assignments: ScopedRoles[];
  row_version: number;
  created_at: string;
  updated_at: string;
}

export interface CursorPage<T> {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface Project {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  description: string | null;
  status: "ACTIVE" | "ARCHIVED";
  row_version: number;
  created_at: string;
  updated_at: string;
}

export type Engine = "MYSQL_8" | "POSTGRESQL_15";

export interface DatasourceSummary {
  id: string;
  project_id: string;
  name: string;
  description: string | null;
  engine: Engine;
  endpoint_redacted: "REDACTED";
  credential_configured: boolean;
  current_revision_id: string;
  current_revision_no: number;
  credential_status: "READY" | "UNAVAILABLE";
  last_test_status: "SUCCEEDED" | "FAILED" | null;
  last_tested_at: string | null;
  last_test_error_code: string | null;
  status: "ACTIVE" | "DISABLED" | "DELETED";
  row_version: number;
  created_at: string;
  updated_at: string;
}

export interface DatasourceRevision {
  id: string;
  datasource_id: string;
  revision_no: number;
  endpoint_policy_revision_id: string;
  physical_endpoint_identity_id: string;
  engine: Engine;
  host: string;
  port: number;
  database_name: string;
  default_schema: string;
  username: string;
  ssl_mode: "DISABLE" | "REQUIRE" | "VERIFY_CA" | "VERIFY_FULL";
  connection_options: Record<string, unknown>;
  config_hash: string;
  created_by: string;
  created_at: string;
}

export interface DatasourceAdminDetail {
  id: string;
  project_id: string;
  name: string;
  description: string | null;
  engine: Engine;
  current_revision: DatasourceRevision;
  current_secret: {
    secret_version: number;
    status: "ACTIVE" | "RETIRED" | "REVOKED" | "COMPROMISED";
    status_reason_code: string | null;
    status_changed_at: string;
    created_at: string;
    active_envelope: Record<string, unknown> | null;
  };
  status: "ACTIVE" | "DISABLED" | "DELETED";
  row_version: number;
  created_at: string;
  updated_at: string;
}

export interface DatasourceTestResult {
  status: "SUCCEEDED" | "FAILED";
  tested_at: string;
  latency_ms: number;
  server_version: string | null;
  error_code: string | null;
  message: string;
  request_id: string;
}

export interface ColumnSchema {
  name: string;
  ordinal: number;
  native_type: string;
  logical_type: OracleLogicalType | null;
  nullable: boolean;
  primary_key: boolean;
  generated: boolean;
  identity: boolean;
  character_maximum_length: number | null;
  numeric_precision: number | null;
  numeric_scale: number | null;
  datetime_precision: number | null;
  oracle_supported: boolean;
  unsupported_reason:
    | "BINARY_FLOAT_UNSUPPORTED"
    | "NATIVE_TYPE_UNSUPPORTED"
    | "GENERATED_COLUMN_UNSUPPORTED"
    | null;
}

export interface TableSchema {
  schema_name: string;
  table_name: string;
  physical_table_identity_hash: string;
  columns: ColumnSchema[];
  schema_hash: string;
  oracle_compatible: boolean;
  target_insert_compatible: boolean;
  incompatibility_reasons: Array<
    | "UNSUPPORTED_COLUMN_TYPE"
    | "GENERATED_COLUMN_PRESENT"
    | "ENABLED_TRIGGER_PRESENT"
    | "PARTITIONED_TABLE_UNSUPPORTED"
    | "ROW_SECURITY_ENABLED"
  >;
  captured_at: string;
}

export type OracleLogicalType =
  | "INTEGER"
  | "DECIMAL"
  | "TEXT"
  | "BOOLEAN"
  | "DATE"
  | "TIME"
  | "TIMESTAMP"
  | "BINARY";

export interface JobSpecEndpoint {
  datasource_id: string;
  datasource_revision_id: string;
  plugin_name: "mysqlreader" | "postgresqlreader" | "mysqlwriter" | "postgresqlwriter";
  table: {
    schema_name: string;
    table_name: string;
  };
}

export interface ColumnMapping {
  source_column: string;
  source_ordinal: number;
  source_type: string;
  source_nullable: boolean;
  target_column: string;
  target_ordinal: number;
  target_type: string;
  target_nullable: boolean;
  oracle_logical_type: OracleLogicalType;
  compatibility: "EXACT" | "WIDENING";
}

export interface JobSpec {
  schema_version: "1.0";
  source: JobSpecEndpoint;
  target: JobSpecEndpoint;
  selection_mode: "ALL_COLUMNS" | "SELECTED_COLUMNS";
  mappings: ColumnMapping[];
  source_consistency_mode: "OPERATOR_QUIESCED";
  target_precondition: "EMPTY_AND_VERIFIABLE";
  write_semantics: "INSERT_ONLY_ONCE";
  duplicate_policy: "REJECT_NONEMPTY_TARGET";
  partial_write_policy: "MANUAL_REMEDIATE";
  write_policy: {
    mode: "INSERT";
    target_table_must_exist: true;
    target_table_must_be_empty: true;
    platform_may_mutate_target_before_run: false;
  };
  execution_policy: {
    channel: number;
    timeout_seconds: number;
    dirty_data_limit: {
      record_count: 0;
      percentage: 0;
    };
  };
}

export type JobStatus = "DRAFT" | "VALID" | "PUBLISHED" | "ARCHIVED";

export interface SyncJob {
  id: string;
  project_id: string;
  name: string;
  description: string | null;
  status: JobStatus;
  draft_spec: JobSpec;
  draft_spec_hash: string;
  validated_spec_hash: string | null;
  latest_published_version_id: string | null;
  latest_published_version_no: number | null;
  latest_execution_process_state: ProcessState | null;
  latest_execution_at: string | null;
  row_version: number;
  created_at: string;
  updated_at: string;
}

export interface ValidationIssue {
  code: string;
  path: string;
  message: string;
}

export interface ValidationReport {
  valid: boolean;
  draft_spec_hash: string;
  source_schema_hash: string | null;
  target_schema_hash: string | null;
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
}

export interface JobPreview {
  draft_spec_hash: string;
  redacted_datax_json: Record<string, unknown>;
  executable: false;
  warnings: ValidationIssue[];
}

export interface JobVersion {
  id: string;
  job_id: string;
  version_no: number;
  spec: JobSpec;
  spec_hash: string;
  version_artifact_hash: string;
  published_by: string;
  published_at: string;
  datax_release: "datax_v202309";
  reader_plugin: "mysqlreader" | "postgresqlreader";
  writer_plugin: "mysqlwriter" | "postgresqlwriter";
  [key: string]: unknown;
}

export type ProcessState =
  | "QUEUED"
  | "STARTING"
  | "RUNNING"
  | "VERIFYING"
  | "SUCCEEDED"
  | "FAILED"
  | "TIMED_OUT"
  | "CANCEL_REQUESTED"
  | "CANCELED"
  | "LOST";
export type DataEffect = "NONE" | "POSSIBLE" | "CONFIRMED" | "UNKNOWN";
export type VerificationState = "NOT_STARTED" | "VERIFYING" | "PASSED" | "FAILED" | "INCONCLUSIVE";
export type TargetExclusivityStatus = "ACTIVE" | "REVOKED" | "EXPIRED";

export interface TargetExclusivityConfirmation {
  statement_version: "1.0";
  confirmed: true;
  confirmed_at: string;
  valid_until: string;
  responsible_party: "OPERATOR" | "DBA";
  note?: string | null;
}

export interface Execution {
  id: string;
  project_id: string;
  job_id: string;
  job_version_id: string;
  rerun_of_execution_id: string | null;
  requested_by: string;
  process_state: ProcessState;
  data_effect: DataEffect;
  verification_state: VerificationState;
  target_exclusivity_confirmation: TargetExclusivityConfirmation;
  target_exclusivity_status: TargetExclusivityStatus;
  target_exclusivity_revoked_at: string | null;
  target_exclusivity_revocation_reason: string | null;
  target_copy_lock: {
    state: "RESERVED" | "ACTIVE" | "RECOVERY_REQUIRED" | "RELEASED";
    [key: string]: unknown;
  };
  runtime_snapshot: Record<string, unknown> | null;
  verification_summary: Record<string, unknown> | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  failure_code: string | null;
  failure_message: string | null;
  log_incomplete: boolean;
  log_dropped_bytes: number;
  run_summary: {
    records_read: number;
    records_written: number;
    records_failed: number;
    bytes_read: number;
    average_bytes_per_second: number;
    average_records_per_second: number;
  } | null;
  [key: string]: unknown;
}

export interface RecoveryGate {
  id: string;
  execution_id: string;
  target_namespace_id: string;
  status: "OPEN" | "REMEDIATION_SUBMITTED" | "VERIFIED" | "REJECTED";
  data_effect_at_open: DataEffect;
  remediation_confirmation: Record<string, unknown> | null;
  target_empty_evidence: Record<string, unknown> | null;
  latest_recovery_probe_id: string | null;
  submitted_at: string | null;
  verified_at: string | null;
  reason_code: string | null;
}

export interface LogLine {
  sequence: number;
  timestamp: string;
  stream: "STDOUT" | "STDERR" | "SYSTEM";
  level: "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR" | "UNKNOWN";
  message: string;
  line_truncated: boolean;
  raw_received_bytes: number;
  redacted_received_bytes: number;
  stored_bytes: number;
  dropped_bytes: number;
}

export type LogGapReason =
  | "LINE_LIMIT"
  | "EXECUTION_LIMIT"
  | "RING_EVICTION"
  | "SOURCE_READ_ERROR"
  | "DECODE_ERROR"
  | "REDACTION_FAILURE"
  | "STORAGE_FAILURE"
  | "FENCE_LOST";

export interface LogGap {
  gap_no: number;
  reason: LogGapReason;
  after_sequence: number | null;
  before_sequence: number | null;
  raw_received_bytes: number;
  redacted_received_bytes: number;
  stored_bytes: number;
  dropped_bytes: number;
  detected_at: string;
  evidence_hash: string;
}

export type LogTruncationReason =
  | "NONE"
  | "EXECUTION_LIMIT"
  | "LINE_LIMIT"
  | "RING_EVICTION";

export interface LogPage {
  items: LogLine[];
  next_cursor: string;
  eof: boolean;
  redaction_rules_version: string;
  truncated: boolean;
  incomplete: boolean;
  raw_received_bytes: number;
  redacted_received_bytes: number;
  stored_bytes: number;
  reason: LogTruncationReason;
  dropped_bytes: number;
  first_truncated_sequence: number | null;
  gap_count: number;
  gaps: LogGap[];
  expires_at: string;
}

export interface DashboardResponse {
  project_id: string;
  window: { from: string; to: string };
  job_counts: {
    total: number;
    draft: number;
    valid: number;
    published: number;
    archived: number;
    executable: number;
  };
  execution_total: number;
  execution_state_counts: Record<ProcessState, number>;
  verification_state_counts: Record<VerificationState, number>;
  data_effect_counts: Record<DataEffect, number>;
  success_rate: { numerator: number; denominator: number; ratio: number | null };
  unresolved_failure_count: number;
  verified_records: { value: number; complete: boolean; missing_verification_count: number };
  recent_executions: Array<{
    execution_id: string;
    job_id: string;
    job_version_id: string;
    job_name: string;
    process_state: ProcessState;
    data_effect: DataEffect;
    verification_state: VerificationState;
    queued_at: string;
    started_at: string | null;
    finished_at: string | null;
    failure_code: string | null;
  }>;
  runtime: {
    worker_online: boolean;
    runtime_ready: boolean;
    oracle_ready: boolean;
    datax_release: "datax_v202309" | null;
    version_match: boolean;
  };
  generated_at: string;
}

export interface EndpointPolicyRevision {
  id: string;
  endpoint_policy_id: string;
  revision_no: number;
  engine: Engine;
  host_kind: "EXACT_FQDN" | "EXACT_IP";
  host_value: string;
  allowed_cidrs: string[];
  allowed_ports: number[];
  tls_required: boolean;
  dns_ttl_ceiling_seconds: number;
  resolver_policy_version: string;
  egress_policy_version: string;
  policy_hash: string;
  created_by: string;
  created_at: string;
}

export interface EndpointPolicy {
  id: string;
  organization_id: string;
  name: string;
  current_revision_id: string;
  current_revision_no: number;
  current_revision: EndpointPolicyRevision;
  status: "ACTIVE" | "DISABLED";
  row_version: number;
}

export type EndpointPolicySummary = EndpointPolicy;

export interface EndpointPolicyInput {
  name: string;
  engine: Engine;
  host_kind: "EXACT_FQDN" | "EXACT_IP";
  host_value: string;
  allowed_cidrs: string[];
  allowed_ports: number[];
  tls_required: boolean;
  dns_ttl_ceiling_seconds: number;
}

export type EndpointPolicyPatch = Omit<EndpointPolicyInput, "engine"> & {
  status: "ACTIVE" | "DISABLED";
};

export interface ProjectMember {
  organization_member_id: string;
  user: UserSummary;
  roles: Role[];
}

export type DatasourceUsage = "SOURCE_USE" | "TARGET_USE";

export interface DatasourceUsageGrant {
  id: string;
  datasource_id: string;
  organization_member_id: string;
  usage: DatasourceUsage;
  status: "ACTIVE" | "REVOKED";
  granted_by: string;
  granted_at: string;
}

export interface TransferPolicyApproval {
  id: string;
  approved_by: string;
  decision: TransferPolicyDecision;
  comment: string | null;
  decided_at: string;
}

export type TransferPolicyDecision = "APPROVED" | "REJECTED";

export interface TransferPolicyScopeSide {
  physical_endpoint_identity_id: string;
  catalog: string;
  schema: string;
  table: string;
  allowed_columns: string[];
}

export interface TransferPolicyScope {
  schema_version: "1.0";
  source: TransferPolicyScopeSide;
  target: TransferPolicyScopeSide;
}

export interface TransferPolicyScopeInputSide {
  catalog: string;
  schema: string;
  table: string;
  selection_mode: "ALL_COLUMNS" | "SELECTED_COLUMNS";
  allowed_columns: string[];
}

export interface TransferPolicyScopeInput {
  schema_version: "1.0";
  source: TransferPolicyScopeInputSide;
  target: TransferPolicyScopeInputSide;
}

export type TransferPolicyClassification = "STANDARD" | "SENSITIVE";
export type TransferPolicyStatus =
  | "DRAFT"
  | "PENDING_APPROVAL"
  | "ACTIVE"
  | "REJECTED"
  | "REVOKED";

export interface TransferPolicy {
  id: string;
  project_id: string;
  source_datasource_revision_id: string;
  target_datasource_revision_id: string;
  source_physical_endpoint_identity_id: string;
  target_physical_endpoint_identity_id: string;
  scope_json: TransferPolicyScope;
  scope_hash: string;
  classification: TransferPolicyClassification;
  status: TransferPolicyStatus;
  requested_by: string;
  approvals: TransferPolicyApproval[];
  activated_at: string | null;
  row_version: number;
}

export interface TransferPolicyCreateInput {
  source_datasource_revision_id: string;
  target_datasource_revision_id: string;
  requested_scope: TransferPolicyScopeInput;
  classification: TransferPolicyClassification;
}

export interface TransferPolicyPatchInput {
  source_datasource_revision_id?: string;
  target_datasource_revision_id?: string;
  requested_scope?: TransferPolicyScopeInput;
  classification?: TransferPolicyClassification;
  status?: "REVOKED";
}

export interface AuditEvent {
  schema_version: "1.0";
  event_id: string;
  organization_id: string;
  sequence: number;
  project_id: string | null;
  occurred_at: string;
  action: string;
  actor: {
    kind: "USER" | "SYSTEM";
    user_id: string | null;
    display_name: string | null;
  };
  target: {
    type: string;
    id: string | null;
    name: string | null;
  };
  request: {
    request_id: string;
    source_ip: string | null;
    user_agent: string | null;
  };
  outcome: "SUCCEEDED" | "DENIED" | "FAILED";
  reason_code: string | null;
  changes: {
    before_hash: string | null;
    after_hash: string | null;
    changed_fields: string[];
  };
  metadata: Record<string, string | number | boolean | string[] | null>;
  integrity: {
    algorithm: "SHA-256";
    canonicalization: "RFC8785";
    chain_scope: "ORGANIZATION_SEQUENCE";
    previous_hash: string | null;
    event_hash: string;
  };
}
