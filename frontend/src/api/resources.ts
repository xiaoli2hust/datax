import type {
  AuditEvent,
  CursorPage,
  DashboardResponse,
  DatasourceAdminDetail,
  DatasourceSummary,
  DatasourceTestResult,
  DatasourceUsage,
  DatasourceUsageGrant,
  EndpointPolicy,
  EndpointPolicyInput,
  EndpointPolicyPatch,
  EndpointPolicySummary,
  Execution,
  JobPreview,
  JobVersion,
  LogPage,
  Project,
  ProjectMember,
  ProjectRole,
  RecoveryGate,
  SyncJob,
  TableSchema,
  TransferPolicy,
  TransferPolicyCreateInput,
  TransferPolicyDecision,
  TransferPolicyPatchInput,
  User,
  ValidationReport,
} from "../types";

import {
  apiDelete,
  apiDownload,
  apiGet,
  apiPatch,
  apiPost,
  apiPut,
  newIdempotencyKey,
  type ApiDownloadResponse,
  weakEtag,
} from "./client";

function queryString(params: Record<string, string | number | boolean | null | undefined>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") query.set(key, String(value));
  }
  const serialized = query.toString();
  return serialized.length > 0 ? `?${serialized}` : "";
}

export function listUsers(cursor?: string): Promise<CursorPage<User>> {
  return apiGet(`/users${queryString({ cursor, limit: 50 })}`);
}

export function createUser(input: {
  email: string;
  display_name: string;
  temporary_password: string;
}, idempotencyKey = newIdempotencyKey()): Promise<User> {
  return apiPost("/users", input, { idempotencyKey });
}

export function listProjects(cursor?: string): Promise<CursorPage<Project>> {
  return apiGet(`/projects${queryString({ cursor, limit: 50 })}`);
}

export function createProject(input: {
  name: string;
  slug: string;
  description: string | null;
}, idempotencyKey = newIdempotencyKey()): Promise<Project> {
  return apiPost("/projects", input, { idempotencyKey });
}

export function updateProject(
  project: Project,
  input: { name?: string; description?: string | null; status?: "ARCHIVED" },
): Promise<Project> {
  return apiPatch(`/projects/${project.id}`, input, { ifMatch: weakEtag(project.row_version) });
}

export function getDashboard(projectId: string, from: string, to: string): Promise<DashboardResponse> {
  return apiGet(`/projects/${projectId}/dashboard${queryString({ from, to })}`);
}

export function listEndpointPolicies(): Promise<CursorPage<EndpointPolicySummary>> {
  return apiGet("/endpoint-policies?limit=200");
}

export function createEndpointPolicy(
  input: EndpointPolicyInput,
  idempotencyKey = newIdempotencyKey(),
): Promise<EndpointPolicy> {
  return apiPost("/endpoint-policies", input, { idempotencyKey });
}

export function updateEndpointPolicy(
  policy: EndpointPolicy,
  input: EndpointPolicyPatch,
): Promise<EndpointPolicy> {
  return apiPatch(`/endpoint-policies/${policy.id}`, input, {
    ifMatch: weakEtag(policy.row_version),
  });
}

export function getEndpointPolicy(policyId: string): Promise<EndpointPolicy> {
  return apiGet(`/endpoint-policies/${policyId}`);
}

export function listDatasources(
  projectId: string,
  cursor?: string,
  engine?: DatasourceSummary["engine"],
  limit = 50,
): Promise<CursorPage<DatasourceSummary>> {
  return apiGet(
    `/projects/${projectId}/datasources${queryString({
      cursor,
      engine,
      limit,
    })}`,
  );
}

export function createDatasource(
  projectId: string,
  input: {
    name: string;
    description: string | null;
    endpoint_policy_id: string;
    engine: "MYSQL_8" | "POSTGRESQL_15";
    host: string;
    port: number;
    database_name: string;
    default_schema: string;
    username: string;
    password: string;
    ssl_mode: "DISABLE" | "REQUIRE" | "VERIFY_CA" | "VERIFY_FULL";
  },
  idempotencyKey = newIdempotencyKey(),
): Promise<DatasourceAdminDetail> {
  return apiPost(`/projects/${projectId}/datasources`, input, {
    idempotencyKey,
  });
}

export function getDatasourceAdminDetail(datasourceId: string): Promise<DatasourceAdminDetail> {
  return apiGet(`/datasources/${datasourceId}/admin-detail`);
}

export type DatasourcePatchInput = Partial<{
  name: string;
  description: string | null;
  endpoint_policy_id: string;
  engine: DatasourceSummary["engine"];
  host: string;
  port: number;
  database_name: string;
  default_schema: string;
  username: string;
  password: string;
  ssl_mode: DatasourceAdminDetail["current_revision"]["ssl_mode"];
  status: "ACTIVE" | "DISABLED";
}>;

export function updateDatasource(
  datasource: Pick<DatasourceSummary, "id" | "row_version">,
  input: DatasourcePatchInput,
): Promise<DatasourceAdminDetail> {
  return apiPatch(`/datasources/${datasource.id}`, input, {
    ifMatch: weakEtag(datasource.row_version),
  });
}

export function deleteDatasource(
  datasource: Pick<DatasourceSummary, "id" | "row_version">,
): Promise<null> {
  return apiDelete(`/datasources/${datasource.id}`, {
    ifMatch: weakEtag(datasource.row_version),
  });
}

export function testDatasource(datasourceId: string): Promise<DatasourceTestResult> {
  return apiPost(`/datasources/${datasourceId}/test`);
}

export function listDatasourceTables(
  datasourceId: string,
  params: { schemaName?: string; tableName?: string; cursor?: string } = {},
): Promise<CursorPage<TableSchema>> {
  return apiGet(
    `/datasources/${datasourceId}/schema/tables${queryString({
      schema_name: params.schemaName,
      table_name: params.tableName,
      cursor: params.cursor,
      limit: 200,
    })}`,
  );
}

export function listProjectMembers(
  projectId: string,
  cursor?: string,
): Promise<CursorPage<ProjectMember>> {
  return apiGet(
    `/projects/${projectId}/members${queryString({ cursor, limit: 200 })}`,
  );
}

export function replaceProjectMemberRoles(
  projectId: string,
  userId: string,
  roles: ProjectRole[],
): Promise<ProjectMember> {
  return apiPut(`/projects/${projectId}/members/${userId}/roles`, { roles });
}

export function listDatasourceUsageGrants(
  datasourceId: string,
  cursor?: string,
): Promise<CursorPage<DatasourceUsageGrant>> {
  return apiGet(
    `/datasources/${datasourceId}/grants${queryString({
      cursor,
      limit: 200,
    })}`,
  );
}

export function replaceDatasourceUsageGrants(
  datasourceId: string,
  memberId: string,
  usages: DatasourceUsage[],
): Promise<CursorPage<DatasourceUsageGrant>> {
  return apiPut(`/datasources/${datasourceId}/grants/${memberId}`, {
    usages,
  });
}

export function listTransferPolicies(
  projectId: string,
  cursor?: string,
): Promise<CursorPage<TransferPolicy>> {
  return apiGet(
    `/projects/${projectId}/transfer-policies${queryString({
      cursor,
      limit: 200,
    })}`,
  );
}

export function getTransferPolicy(
  transferPolicyId: string,
): Promise<TransferPolicy> {
  return apiGet(`/transfer-policies/${transferPolicyId}`);
}

export function createTransferPolicy(
  projectId: string,
  input: TransferPolicyCreateInput,
  idempotencyKey = newIdempotencyKey(),
): Promise<TransferPolicy> {
  return apiPost(`/projects/${projectId}/transfer-policies`, input, {
    idempotencyKey,
  });
}

export function updateTransferPolicy(
  policy: TransferPolicy,
  input: TransferPolicyPatchInput,
): Promise<TransferPolicy> {
  return apiPatch(`/transfer-policies/${policy.id}`, input, {
    ifMatch: weakEtag(policy.row_version),
  });
}

export function submitTransferPolicy(
  policy: TransferPolicy,
  idempotencyKey = newIdempotencyKey(),
): Promise<TransferPolicy> {
  return apiPost(
    `/transfer-policies/${policy.id}/submit`,
    { expected_scope_hash: policy.scope_hash },
    { idempotencyKey },
  );
}

export function decideTransferPolicy(
  policy: TransferPolicy,
  input: {
    decision: TransferPolicyDecision;
    comment: string | null;
  },
  idempotencyKey = newIdempotencyKey(),
): Promise<TransferPolicy> {
  return apiPost(
    `/transfer-policies/${policy.id}/approvals`,
    {
      decision: input.decision,
      expected_scope_hash: policy.scope_hash,
      comment: input.comment,
    },
    { idempotencyKey },
  );
}

export function listProjectAuditEvents(
  projectId: string,
  filters: {
    action?: string;
    outcome?: AuditEvent["outcome"];
    actorId?: string;
    from?: string;
    to?: string;
    cursor?: string;
  } = {},
): Promise<CursorPage<AuditEvent>> {
  return apiGet(
    `/projects/${projectId}/audit-events${queryString({
      action: filters.action,
      outcome: filters.outcome,
      actor_id: filters.actorId,
      from: filters.from,
      to: filters.to,
      cursor: filters.cursor,
      limit: 100,
    })}`,
  );
}

export interface JobListFilters {
  query?: string;
  status?: SyncJob["status"];
  readerPlugin?: "mysqlreader" | "postgresqlreader";
  writerPlugin?: "mysqlwriter" | "postgresqlwriter";
  latestExecutionState?: Execution["process_state"];
  hasPublishedVersion?: boolean;
  cursor?: string;
}

export function listJobs(
  projectId: string,
  filters: JobListFilters = {},
): Promise<CursorPage<SyncJob>> {
  return apiGet(
    `/projects/${projectId}/jobs${queryString({
      q: filters.query,
      status: filters.status,
      reader_plugin: filters.readerPlugin,
      writer_plugin: filters.writerPlugin,
      latest_execution_state: filters.latestExecutionState,
      has_published_version: filters.hasPublishedVersion,
      cursor: filters.cursor,
      limit: 50,
    })}`,
  );
}

export function createJob(
  projectId: string,
  input: { name: string; description: string | null; draft_spec: SyncJob["draft_spec"] },
  idempotencyKey = newIdempotencyKey(),
): Promise<SyncJob> {
  return apiPost(`/projects/${projectId}/jobs`, input, {
    idempotencyKey,
  });
}

export function updateJob(
  job: SyncJob,
  input: {
    name?: string;
    description?: string | null;
    draft_spec?: SyncJob["draft_spec"];
    status?: "ARCHIVED";
  },
): Promise<SyncJob> {
  return apiPatch(`/jobs/${job.id}`, input, {
    ifMatch: weakEtag(job.row_version),
  });
}

export function validateJob(jobId: string): Promise<ValidationReport> {
  return apiPost(`/jobs/${jobId}/validate`);
}

export function previewJob(jobId: string): Promise<JobPreview> {
  return apiPost(`/jobs/${jobId}/preview`);
}

export function publishJob(job: SyncJob, idempotencyKey = newIdempotencyKey()): Promise<JobVersion> {
  return apiPost(
    `/jobs/${job.id}/versions`,
    { expected_draft_spec_hash: job.validated_spec_hash ?? job.draft_spec_hash },
    {
      idempotencyKey,
      ifMatch: weakEtag(job.row_version),
    },
  );
}

export function listJobVersions(
  jobId: string,
  cursor?: string,
): Promise<CursorPage<JobVersion>> {
  return apiGet(
    `/jobs/${jobId}/versions${queryString({ cursor, limit: 50 })}`,
  );
}

export function listExecutions(
  projectId: string,
  filters: {
    query?: string;
    processState?: string;
    dataEffect?: string;
    verificationState?: string;
    targetExclusivityStatus?: string;
    jobId?: string;
    jobVersionId?: string;
    requestedBy?: string;
    from?: string;
    to?: string;
    isRerun?: boolean;
    unresolvedFailure?: boolean;
    cursor?: string;
  } = {},
): Promise<CursorPage<Execution>> {
  return apiGet(
    `/projects/${projectId}/executions${queryString({
      q: filters.query,
      process_state: filters.processState,
      data_effect: filters.dataEffect,
      verification_state: filters.verificationState,
      target_exclusivity_status: filters.targetExclusivityStatus,
      job_id: filters.jobId,
      job_version_id: filters.jobVersionId,
      requested_by: filters.requestedBy,
      from: filters.from,
      to: filters.to,
      is_rerun: filters.isRerun,
      unresolved_failure: filters.unresolvedFailure,
      cursor: filters.cursor,
      limit: 50,
    })}`,
  );
}

export function createExecution(
  jobId: string,
  input: {
    job_version_id: string;
    source_quiescence_confirmation: {
      confirmed: true;
      confirmed_at: string;
      note?: string | null;
    };
    target_exclusivity_confirmation: {
      statement_version: "1.0";
      confirmed: true;
      confirmed_at: string;
      valid_until: string;
      responsible_party: "OPERATOR" | "DBA";
      note?: string | null;
    };
  },
  idempotencyKey = newIdempotencyKey(),
): Promise<Execution> {
  return apiPost(`/jobs/${jobId}/executions`, input, {
    idempotencyKey,
  });
}

export function getExecution(executionId: string): Promise<Execution> {
  return apiGet(`/executions/${executionId}`);
}

export function cancelExecution(
  executionId: string,
  reason?: string,
  idempotencyKey = newIdempotencyKey(),
): Promise<Record<string, unknown>> {
  return apiPost(
    `/executions/${executionId}/cancel`,
    reason?.trim() ? { reason: reason.trim() } : {},
    { idempotencyKey },
  );
}

export function revokeTargetExclusivity(
  execution: Execution,
  reason:
    | "OPERATOR_REVOKED"
    | "DBA_REVOKED"
    | "EXTERNAL_DML_DDL_REPORTED"
    | "CHANGE_FREEZE_BROKEN",
  note?: string,
  idempotencyKey = newIdempotencyKey(),
  reportedAt = new Date().toISOString(),
): Promise<Execution> {
  return apiPost(
    `/executions/${execution.id}/target-exclusivity/revoke`,
    {
      statement_version: "1.0",
      responsible_party: execution.target_exclusivity_confirmation.responsible_party,
      reason,
      reported_at: reportedAt,
      note: note?.trim() || null,
    },
    { idempotencyKey },
  );
}

export function getRecoveryGate(executionId: string): Promise<RecoveryGate> {
  return apiGet(`/executions/${executionId}/recovery`);
}

export function submitRemediation(
  executionId: string,
  input: {
    action: "CLEANED_TARGET" | "RECREATED_TARGET" | "NO_CLEANUP_REQUIRED" | "OTHER_EXTERNAL_ACTION";
    cleanup_performed: boolean;
    reason: string;
    confirmed_at: string;
  },
  idempotencyKey = newIdempotencyKey(),
): Promise<Record<string, unknown>> {
  return apiPost(`/executions/${executionId}/recovery`, input, {
    idempotencyKey,
  });
}

export function rerunExecution(
  executionId: string,
  input: {
    recovery_gate_id: string;
    source_quiescence_confirmation: {
      confirmed: true;
      confirmed_at: string;
      note?: string | null;
    };
    target_exclusivity_confirmation: {
      statement_version: "1.0";
      confirmed: true;
      confirmed_at: string;
      valid_until: string;
      responsible_party: "OPERATOR" | "DBA";
      note?: string | null;
    };
  },
  idempotencyKey = newIdempotencyKey(),
): Promise<Execution> {
  return apiPost(`/executions/${executionId}/rerun`, input, {
    idempotencyKey,
  });
}

export function getExecutionLogs(
  executionId: string,
  cursor?: string,
): Promise<LogPage> {
  return apiGet(
    `/executions/${executionId}/logs${queryString({ cursor, limit: 200 })}`,
  );
}

export function downloadExecutionLogs(
  executionId: string,
): Promise<ApiDownloadResponse> {
  return apiDownload(`/executions/${executionId}/logs/download`);
}
