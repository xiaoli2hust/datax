<script setup lang="ts">
import { ElMessage, ElMessageBox } from "element-plus";
import {
  computed,
  onBeforeUnmount,
  onMounted,
  reactive,
  ref,
  watch,
} from "vue";

import { isApiError, newIdempotencyKey } from "../api/client";
import {
  cancelExecution,
  createExecution,
  downloadExecutionLogs,
  getExecution,
  getExecutionLogs,
  getRecoveryGate,
  listExecutions,
  listJobs,
  listJobVersions,
  rerunExecution,
  revokeTargetExclusivity,
  submitRemediation,
} from "../api/resources";
import EmptyState from "../components/EmptyState.vue";
import ProblemPanel from "../components/ProblemPanel.vue";
import StateBadge from "../components/StateBadge.vue";
import { formatTime, shortId } from "../lib/display";
import type {
  Execution,
  JobVersion,
  LogGap,
  LogLine,
  LogPage,
  LogTruncationReason,
  RecoveryGate,
  SyncJob,
} from "../types";

const props = defineProps<{
  projectId: string;
  canOperate: boolean;
  workerReady: boolean;
  requestedJobId?: string | null;
  requestedExecutionId?: string | null;
}>();

const emit = defineEmits<{
  requestConsumed: [];
}>();

const items = ref<Execution[]>([]);
const jobs = ref<SyncJob[]>([]);
const loading = ref(false);
const loadingMore = ref(false);
const error = ref<unknown>(null);
const nextCursor = ref<string | null>(null);
const hasMore = ref(false);
const actionLoading = ref(false);
const filters = reactive({
  query: "",
  processState: "",
  dataEffect: "",
  verificationState: "",
  targetExclusivityStatus: "",
  jobId: "",
  jobVersionId: "",
  requestedBy: "",
  from: "",
  to: "",
  rerun: "",
});
const runVisible = ref(false);
const runIdempotencyKey = ref(newIdempotencyKey());
const runOutcomeUncertain = ref(false);
const runRequestSnapshot = ref<Parameters<typeof createExecution>[1] | null>(null);
const versions = ref<JobVersion[]>([]);
const versionsLoading = ref(false);
const runForm = reactive({
  jobId: "",
  versionId: "",
  sourceConfirmed: false,
  sourceNote: "",
  targetConfirmed: false,
  responsibleParty: "OPERATOR" as "OPERATOR" | "DBA",
  validUntil: "",
  targetNote: "",
});
const detailVisible = ref(false);
const detail = ref<Execution | null>(null);
const detailLoading = ref(false);
const detailError = ref<unknown>(null);
const revokeVisible = ref(false);
const revokeIdempotencyKey = ref(newIdempotencyKey());
const revokeReportedAt = ref(new Date().toISOString());
const revokeForm = reactive({
  reason: "CHANGE_FREEZE_BROKEN" as
    | "OPERATOR_REVOKED"
    | "DBA_REVOKED"
    | "EXTERNAL_DML_DDL_REPORTED"
    | "CHANGE_FREEZE_BROKEN",
  note: "",
});
const recovery = ref<RecoveryGate | null>(null);
const recoveryError = ref<unknown>(null);
const remediationVisible = ref(false);
const remediationIdempotencyKey = ref(newIdempotencyKey());
const remediationConfirmedAt = ref(new Date().toISOString());
const remediationForm = reactive({
  action: "NO_CLEANUP_REQUIRED" as
    | "CLEANED_TARGET"
    | "RECREATED_TARGET"
    | "NO_CLEANUP_REQUIRED"
    | "OTHER_EXTERNAL_ACTION",
  cleanupPerformed: false,
  reason: "",
});
const logs = ref<LogLine[]>([]);
const logsCursor = ref<string | undefined>();
const logsEof = ref(false);
const logsLoading = ref(false);
const logsError = ref<unknown>(null);
const logsIncomplete = ref(false);
const logsLoaded = ref(false);
const logSnapshot = ref<LogPage | null>(null);
const logIntegrityError = ref<Error | null>(null);
const logDownloadError = ref<unknown>(null);
const logDownloading = ref(false);
const logDownloadMeta = ref<LogDownloadMetadata | null>(null);
const logAutoRefreshActive = ref(false);
const logAutoRefreshPolls = ref(0);
const logAutoRefreshLimitReached = ref(false);
const logSearch = ref("");
const cancelRequests = new Map<string, { key: string; reason: string }>();
type RerunRequest = Parameters<typeof rerunExecution>[1];
const rerunRequests = new Map<string, { key: string; request: RerunRequest }>();
let refreshTimer: number | undefined;
let logRefreshTimer: number | undefined;
let logAutoRefreshDeadline = 0;

const terminalStates = new Set(["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED", "LOST"]);
const cancellableStates = new Set([
  "QUEUED",
  "STARTING",
  "RUNNING",
  "VERIFYING",
  "CANCEL_REQUESTED",
]);
const recoverableStates = new Set(["FAILED", "TIMED_OUT", "CANCELED", "LOST"]);
const LOG_AUTO_REFRESH_INTERVAL_MS = 3000;
const LOG_AUTO_REFRESH_MAX_POLLS = 20;

interface LogDownloadMetadata {
  filename: string;
  redactionRulesVersion: string;
  contentSha256: string;
  truncated: boolean;
  incomplete: boolean;
  rawReceivedBytes: number;
  redactedReceivedBytes: number;
  storedBytes: number;
  droppedBytes: number;
  gapCount: number;
  truncationReason: LogTruncationReason;
}

const selectedRunJob = computed(() => jobs.value.find((job) => job.id === runForm.jobId));
const canSubmitRun = computed(() => {
  if (!props.workerReady || !runForm.jobId || !runForm.versionId) return false;
  if (!runForm.sourceConfirmed || !runForm.targetConfirmed || !runForm.validUntil) return false;
  const expiry = new Date(runForm.validUntil).getTime();
  return Number.isFinite(expiry) && expiry > Date.now();
});
const filteredLogs = computed(() => {
  const needle = logSearch.value.trim().toLocaleLowerCase();
  if (!needle) return logs.value;
  return logs.value.filter((line) => line.message.toLocaleLowerCase().includes(needle));
});
const logEmptyTitle = computed(() => {
  if (!logsLoaded.value) return "正在读取真实日志";
  if (logSnapshot.value?.incomplete)
    return "没有可安全显示的日志正文";
  if (detail.value && !terminalStates.has(detail.value.process_state))
    return "当前尚未产生持久化日志";
  return "服务端明确返回 0 字节日志";
});
const logEmptyDescription = computed(() => {
  if (!logsLoaded.value)
    return "只会显示后端通过不透明 cursor 返回的脱敏文本。";
  if (logSnapshot.value?.incomplete)
    return "服务端已登记缺口；请查看上方原因和证据哈希，不能把空正文当作完整日志。";
  if (detail.value && !terminalStates.has(detail.value.process_state))
    return "执行仍在推进，页面只会进行最多 20 次、约 60 秒的有限自动刷新。";
  return "这只表示服务端本次明确记账为未接收、未存储日志，不构成执行成功或核验通过的证据。";
});

function defaultValidUntil(): string {
  const value = new Date(Date.now() + 4 * 60 * 60 * 1000);
  const offset = value.getTimezoneOffset() * 60_000;
  return new Date(value.getTime() - offset).toISOString().slice(0, 16);
}

async function load(background = false, append = false): Promise<void> {
  if (append) loadingMore.value = true;
  else if (!background) loading.value = true;
  error.value = null;
  try {
    const response = await listExecutions(props.projectId, {
      query: filters.query.trim() || undefined,
      processState: filters.processState || undefined,
      dataEffect: filters.dataEffect || undefined,
      verificationState: filters.verificationState || undefined,
      targetExclusivityStatus:
        filters.targetExclusivityStatus || undefined,
      jobId: filters.jobId || undefined,
      jobVersionId: filters.jobVersionId.trim() || undefined,
      requestedBy: filters.requestedBy.trim() || undefined,
      from: localTimeToIso(filters.from),
      to: localTimeToIso(filters.to),
      isRerun:
        filters.rerun === ""
          ? undefined
          : filters.rerun === "true",
      cursor: append ? nextCursor.value ?? undefined : undefined,
    });
    items.value = append
      ? [...items.value, ...response.items]
      : response.items;
    nextCursor.value = response.next_cursor;
    hasMore.value = response.has_more;
    if (detail.value && !terminalStates.has(detail.value.process_state)) {
      detail.value = await getExecution(detail.value.id);
    }
  } catch (caught) {
    error.value = caught;
  } finally {
    if (append) loadingMore.value = false;
    else if (!background) loading.value = false;
  }
}

function localTimeToIso(value: string): string | undefined {
  if (!value) return undefined;
  const timestamp = new Date(value);
  return Number.isFinite(timestamp.getTime())
    ? timestamp.toISOString()
    : undefined;
}

function resetFilters(): void {
  filters.query = "";
  filters.processState = "";
  filters.dataEffect = "";
  filters.verificationState = "";
  filters.targetExclusivityStatus = "";
  filters.jobId = "";
  filters.jobVersionId = "";
  filters.requestedBy = "";
  filters.from = "";
  filters.to = "";
  filters.rerun = "";
  void load();
}

function jobName(jobId: string): string {
  return jobs.value.find((job) => job.id === jobId)?.name ?? shortId(jobId);
}

async function loadJobs(): Promise<void> {
  try {
    const collected: SyncJob[] = [];
    let cursor: string | undefined;
    do {
      const page = await listJobs(props.projectId, { cursor });
      collected.push(...page.items);
      cursor =
        page.has_more && page.next_cursor
          ? page.next_cursor
          : undefined;
    } while (cursor);
    jobs.value = collected;
  } catch (caught) {
    error.value = caught;
    jobs.value = [];
  }
}

async function openRun(jobId?: string): Promise<void> {
  runIdempotencyKey.value = newIdempotencyKey();
  runOutcomeUncertain.value = false;
  runRequestSnapshot.value = null;
  runForm.jobId = jobId ?? "";
  runForm.versionId = "";
  runForm.sourceConfirmed = false;
  runForm.sourceNote = "";
  runForm.targetConfirmed = false;
  runForm.responsibleParty = "OPERATOR";
  runForm.validUntil = defaultValidUntil();
  runForm.targetNote = "";
  versions.value = [];
  error.value = null;
  runVisible.value = true;
  await loadJobs();
  if (runForm.jobId) await jobChanged();
}

async function jobChanged(): Promise<void> {
  versions.value = [];
  runForm.versionId = "";
  if (!runForm.jobId) return;
  versionsLoading.value = true;
  try {
    versions.value = (await listJobVersions(runForm.jobId)).items;
    const job = jobs.value.find((candidate) => candidate.id === runForm.jobId);
    runForm.versionId = job?.latest_published_version_id ?? versions.value[0]?.id ?? "";
  } catch (caught) {
    error.value = caught;
  } finally {
    versionsLoading.value = false;
  }
}

async function submitRun(): Promise<void> {
  if (!canSubmitRun.value) return;
  actionLoading.value = true;
  error.value = null;
  try {
    const confirmedAt = new Date().toISOString();
    const request =
      runRequestSnapshot.value ??
      {
        job_version_id: runForm.versionId,
        source_quiescence_confirmation: {
          confirmed: true as const,
          confirmed_at: confirmedAt,
          note: runForm.sourceNote.trim() || null,
        },
        target_exclusivity_confirmation: {
          statement_version: "1.0" as const,
          confirmed: true as const,
          confirmed_at: confirmedAt,
          valid_until: new Date(runForm.validUntil).toISOString(),
          responsible_party: runForm.responsibleParty,
          note: runForm.targetNote.trim() || null,
        },
      };
    runRequestSnapshot.value = request;
    const execution = await createExecution(
      runForm.jobId,
      request,
      runIdempotencyKey.value,
    );
    runRequestSnapshot.value = null;
    runOutcomeUncertain.value = false;
    runVisible.value = false;
    ElMessage.success("执行已提交，当前只确认排队；完成 DataX 后仍需独立核验。");
    await load();
    await openDetail(execution.id);
  } catch (caught) {
    error.value = caught;
    runOutcomeUncertain.value =
      !isApiError(caught) ||
      caught.problem.retryable ||
      caught.problem.code === "IDEMPOTENCY_IN_PROGRESS";
  } finally {
    actionLoading.value = false;
  }
}

async function openDetail(executionId: string): Promise<void> {
  detailVisible.value = true;
  detailLoading.value = true;
  detailError.value = null;
  recovery.value = null;
  recoveryError.value = null;
  resetLogState();
  try {
    detail.value = await getExecution(executionId);
  } catch (caught) {
    detailError.value = caught;
    detail.value = null;
  } finally {
    detailLoading.value = false;
  }
  if (detail.value?.id !== executionId) return;
  await loadLogs(true);
  if (
    !terminalStates.has(detail.value.process_state) &&
    !logsError.value &&
    !logIntegrityError.value
  ) {
    startLogAutoRefresh();
  }
}

async function requestCancel(): Promise<void> {
  if (!detail.value) return;
  try {
    const previousRequest = cancelRequests.get(detail.value.id);
    const result = await ElMessageBox.prompt(
      "取消会请求 Worker 停止 DataX 进程，但不能撤销已提交到目标库的数据。可填写非敏感原因。",
      "请求取消执行",
      {
        confirmButtonText: "提交取消请求",
        cancelButtonText: "返回",
        inputPlaceholder: "可选原因；不要填写密码或连接串",
        inputValue: previousRequest?.reason ?? "",
        inputType: "textarea",
        type: "warning",
      },
    );
    actionLoading.value = true;
    const request =
      previousRequest?.reason === result.value
        ? previousRequest
        : { key: newIdempotencyKey(), reason: result.value };
    cancelRequests.set(detail.value.id, request);
    await cancelExecution(detail.value.id, request.reason, request.key);
    cancelRequests.delete(detail.value.id);
    ElMessage.success("取消请求已提交，等待 Worker 确认；当前还不能显示“已取消”。");
    detail.value = await getExecution(detail.value.id);
    await load(true);
  } catch (caught) {
    if (caught !== "cancel" && caught !== "close") detailError.value = caught;
  } finally {
    actionLoading.value = false;
  }
}

async function submitRevoke(): Promise<void> {
  if (!detail.value) return;
  actionLoading.value = true;
  detailError.value = null;
  try {
    detail.value = await revokeTargetExclusivity(
      detail.value,
      revokeForm.reason,
      revokeForm.note,
      revokeIdempotencyKey.value,
      revokeReportedAt.value,
    );
    revokeVisible.value = false;
    ElMessage.success("独占窗口破坏报告已保存；本次执行不得成为核验成功。");
    await load(true);
  } catch (caught) {
    detailError.value = caught;
  } finally {
    actionLoading.value = false;
  }
}

async function loadRecovery(): Promise<void> {
  if (!detail.value) return;
  recoveryError.value = null;
  try {
    recovery.value = await getRecoveryGate(detail.value.id);
  } catch (caught) {
    recoveryError.value = caught;
    recovery.value = null;
  }
}

function remediationActionChanged(): void {
  if (remediationForm.action === "NO_CLEANUP_REQUIRED") remediationForm.cleanupPerformed = false;
  if (["CLEANED_TARGET", "RECREATED_TARGET"].includes(remediationForm.action)) {
    remediationForm.cleanupPerformed = true;
  }
}

function openRevoke(): void {
  revokeForm.reason = "CHANGE_FREEZE_BROKEN";
  revokeForm.note = "";
  revokeIdempotencyKey.value = newIdempotencyKey();
  revokeReportedAt.value = new Date().toISOString();
  revokeVisible.value = true;
}

function openRemediation(): void {
  remediationForm.action = "NO_CLEANUP_REQUIRED";
  remediationForm.cleanupPerformed = false;
  remediationForm.reason = "";
  remediationIdempotencyKey.value = newIdempotencyKey();
  remediationConfirmedAt.value = new Date().toISOString();
  remediationVisible.value = true;
}

async function submitRemediationForm(): Promise<void> {
  if (!detail.value || !remediationForm.reason.trim()) return;
  actionLoading.value = true;
  recoveryError.value = null;
  try {
    await submitRemediation(
      detail.value.id,
      {
        action: remediationForm.action,
        cleanup_performed: remediationForm.cleanupPerformed,
        reason: remediationForm.reason.trim(),
        confirmed_at: remediationConfirmedAt.value,
      },
      remediationIdempotencyKey.value,
    );
    remediationVisible.value = false;
    ElMessage.success("处置确认已提交；仍须等待独立 RecoveryProbe 实测目标为空。");
    await loadRecovery();
  } catch (caught) {
    recoveryError.value = caught;
  } finally {
    actionLoading.value = false;
  }
}

async function submitRerun(): Promise<void> {
  if (!detail.value || recovery.value?.status !== "VERIFIED") return;
  try {
    const previousRequest = rerunRequests.get(detail.value.id);
    const result = await ElMessageBox.prompt(
      "恢复后再次执行仍须保持源表静默，并提交新的目标独占截止时间。请输入新的有效期（ISO 8601，例如 2026-08-01T12:00:00Z）。",
      "恢复后再次执行",
      {
        confirmButtonText: "确认并创建新执行",
        cancelButtonText: "取消",
        inputValue:
          previousRequest?.request.target_exclusivity_confirmation.valid_until ??
          new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString(),
        inputValidator: (value) =>
          (Number.isFinite(new Date(value).getTime()) && new Date(value).getTime() > Date.now()) ||
          "截止时间必须晚于当前时间",
        type: "warning",
      },
    );
    actionLoading.value = true;
    const validUntil = new Date(result.value).toISOString();
    const rerunRequest =
      previousRequest?.request.target_exclusivity_confirmation.valid_until === validUntil
        ? previousRequest
        : (() => {
            const confirmedAt = new Date().toISOString();
            return {
              key: newIdempotencyKey(),
              request: {
                recovery_gate_id: recovery.value!.id,
                source_quiescence_confirmation: {
                  confirmed: true as const,
                  confirmed_at: confirmedAt,
                  note: "恢复后再次执行前已重新确认源表静默",
                },
                target_exclusivity_confirmation: {
                  statement_version: "1.0" as const,
                  confirmed: true as const,
                  confirmed_at: confirmedAt,
                  valid_until: validUntil,
                  responsible_party:
                    detail.value!.target_exclusivity_confirmation.responsible_party,
                  note: "恢复后再次执行的新目标外部独占窗口",
                },
              },
            };
          })();
    rerunRequests.set(detail.value.id, rerunRequest);
    const execution = await rerunExecution(
      detail.value.id,
      rerunRequest.request,
      rerunRequest.key,
    );
    rerunRequests.delete(detail.value.id);
    ElMessage.success("新的执行已创建；原执行及其证据保持不变。");
    await load();
    await openDetail(execution.id);
  } catch (caught) {
    if (caught !== "cancel" && caught !== "close") recoveryError.value = caught;
  } finally {
    actionLoading.value = false;
  }
}

async function loadLogs(reset = false): Promise<void> {
  if (!detail.value || logsLoading.value) return;
  const executionId = detail.value.id;
  logsLoading.value = true;
  logsError.value = null;
  if (reset) {
    logs.value = [];
    logsCursor.value = undefined;
    logsEof.value = false;
    logsLoaded.value = false;
    logsIncomplete.value = false;
    logSnapshot.value = null;
    logIntegrityError.value = null;
  }
  try {
    const page = await getExecutionLogs(executionId, logsCursor.value);
    if (detail.value?.id !== executionId) return;
    const contractIssue = validateLogPage(page, reset);
    if (contractIssue) {
      logIntegrityError.value = new Error(contractIssue);
      stopLogAutoRefresh();
      return;
    }
    const known = new Set(logs.value.map((line) => line.sequence));
    logs.value.push(...page.items.filter((line) => !known.has(line.sequence)));
    logs.value.sort((a, b) => a.sequence - b.sequence);
    logsCursor.value = page.next_cursor;
    logsEof.value = page.eof;
    logsIncomplete.value = page.incomplete || page.truncated;
    logsLoaded.value = true;
    logSnapshot.value = page;
  } catch (caught) {
    logsError.value = caught;
    stopLogAutoRefresh();
  } finally {
    logsLoading.value = false;
  }
}

function validateLogPage(page: LogPage, reset: boolean): string | null {
  if (
    typeof page.next_cursor !== "string" ||
    !page.next_cursor ||
    typeof page.redaction_rules_version !== "string" ||
    !page.redaction_rules_version
  ) {
    return "日志响应缺少不透明游标或脱敏规则版本，已停止展示，不能把不完整响应当作日志事实。";
  }
  const counters = [
    page.raw_received_bytes,
    page.redacted_received_bytes,
    page.stored_bytes,
    page.dropped_bytes,
    page.gap_count,
  ];
  if (
    counters.some(
      (value) => !Number.isSafeInteger(value) || value < 0,
    ) ||
    page.redacted_received_bytes !==
      page.stored_bytes + page.dropped_bytes
  ) {
    return "日志字节计数不满足服务端记账契约，已停止展示并禁止据此判断日志完整性。";
  }
  if (
    page.gap_count < page.gaps.length ||
    page.incomplete !== (page.gap_count > 0) ||
    page.truncated !== (page.reason !== "NONE")
  ) {
    return "日志缺口、截断状态与原因互相矛盾，已停止展示。";
  }
  if (
    !Number.isFinite(new Date(page.expires_at).getTime()) ||
    page.gaps.some(
      (gap) =>
        !/^[a-f0-9]{64}$/.test(gap.evidence_hash) ||
        gap.gap_no < 1 ||
        gap.dropped_bytes < 0,
    )
  ) {
    return "日志保留时间或缺口证据格式无效，已停止展示。";
  }

  for (let index = 0; index < page.items.length; index += 1) {
    const current = page.items[index];
    const previous = page.items[index - 1];
    if (
      !current ||
      !Number.isSafeInteger(current.sequence) ||
      current.sequence < 1 ||
      (previous && current.sequence <= previous.sequence)
    ) {
      return "日志序号重复、倒序或无效，疑似游标或存储完整性异常，已停止展示。";
    }
    if (
      previous &&
      current.sequence !== previous.sequence + 1 &&
      page.gap_count === 0
    ) {
      return "日志序号出现未登记缺口，已停止展示；服务端必须先登记 LogGap。";
    }
  }

  const existingSequences = new Set(
    reset ? [] : logs.value.map((line) => line.sequence),
  );
  if (page.items.some((line) => existingSequences.has(line.sequence))) {
    return "日志分页返回了重复序号，已停止展示，避免静默去重掩盖游标异常。";
  }
  const previousLast = reset
    ? undefined
    : logs.value[logs.value.length - 1]?.sequence;
  const firstNew = page.items[0]?.sequence;
  if (
    firstNew !== undefined &&
    previousLast !== undefined &&
    firstNew !== previousLast + 1 &&
    page.gap_count === 0
  ) {
    return "相邻日志页之间存在未登记序号缺口，已停止展示。";
  }
  if (
    reset &&
    firstNew !== undefined &&
    firstNew !== 1 &&
    page.gap_count === 0
  ) {
    return "日志首个序号不是 1 且服务端未登记缺口，已停止展示。";
  }
  if (
    reset &&
    page.items.length === 0 &&
    (page.raw_received_bytes > 0 || page.stored_bytes > 0) &&
    page.gap_count === 0
  ) {
    return "服务端报告已接收或已存储日志字节，却没有返回正文或 LogGap；已按日志缺失处理。";
  }
  if (
    detail.value?.log_incomplete === true &&
    page.incomplete === false
  ) {
    return "执行摘要已标记日志不完整，但日志接口未返回缺口，已停止展示。";
  }
  return null;
}

function resetLogState(): void {
  stopLogAutoRefresh();
  logs.value = [];
  logsCursor.value = undefined;
  logsEof.value = false;
  logsLoading.value = false;
  logsError.value = null;
  logsIncomplete.value = false;
  logsLoaded.value = false;
  logSnapshot.value = null;
  logIntegrityError.value = null;
  logDownloadError.value = null;
  logDownloadMeta.value = null;
  logSearch.value = "";
  logAutoRefreshPolls.value = 0;
  logAutoRefreshLimitReached.value = false;
}

function stopLogAutoRefresh(limitReached = false): void {
  if (logRefreshTimer !== undefined) {
    window.clearInterval(logRefreshTimer);
    logRefreshTimer = undefined;
  }
  logAutoRefreshDeadline = 0;
  logAutoRefreshActive.value = false;
  if (limitReached) logAutoRefreshLimitReached.value = true;
}

function startLogAutoRefresh(): void {
  stopLogAutoRefresh();
  if (
    !detail.value ||
    terminalStates.has(detail.value.process_state)
  ) {
    return;
  }
  logAutoRefreshPolls.value = 0;
  logAutoRefreshLimitReached.value = false;
  logAutoRefreshActive.value = true;
  logAutoRefreshDeadline =
    Date.now() +
    LOG_AUTO_REFRESH_INTERVAL_MS * LOG_AUTO_REFRESH_MAX_POLLS;
  logRefreshTimer = window.setInterval(() => {
    if (Date.now() >= logAutoRefreshDeadline) {
      stopLogAutoRefresh(true);
      return;
    }
    void pollLogs();
  }, LOG_AUTO_REFRESH_INTERVAL_MS);
}

async function pollLogs(): Promise<void> {
  if (
    !detailVisible.value ||
    !detail.value ||
    document.visibilityState !== "visible" ||
    logsLoading.value
  ) {
    return;
  }
  logAutoRefreshPolls.value += 1;
  await loadLogs(false);
  if (
    logsError.value ||
    logIntegrityError.value ||
    !detail.value ||
    terminalStates.has(detail.value.process_state)
  ) {
    stopLogAutoRefresh();
    return;
  }
  if (
    logAutoRefreshPolls.value >= LOG_AUTO_REFRESH_MAX_POLLS ||
    Date.now() >= logAutoRefreshDeadline
  ) {
    stopLogAutoRefresh(true);
  }
}

async function downloadLogs(): Promise<void> {
  if (!detail.value || logDownloading.value) return;
  const executionId = detail.value.id;
  logDownloading.value = true;
  logDownloadError.value = null;
  try {
    const artifact = await downloadExecutionLogs(executionId);
    if (detail.value?.id !== executionId) return;
    const metadata = parseLogDownloadMetadata(
      artifact.headers,
      artifact.blob,
    );
    const actualSha256 = await sha256Hex(artifact.blob);
    if (actualSha256 !== metadata.contentSha256) {
      throw new Error(
        "下载正文 SHA-256 与服务端 X-Content-SHA256 不一致，疑似传输或内容完整性异常；文件未保存。",
      );
    }
    logDownloadMeta.value = metadata;

    if (
      metadata.incomplete ||
      metadata.truncated ||
      metadata.gapCount > 0
    ) {
      await loadLogs(true);
      try {
        await ElMessageBox.confirm(
          `服务端报告该日志不完整：${metadata.gapCount} 个缺口，丢弃 ${formatBytes(metadata.droppedBytes)}，原因 ${truncationReasonLabel(metadata.truncationReason)}。下载无法恢复缺失内容。`,
          "下载不完整的脱敏日志",
          {
            confirmButtonText: "知悉缺口并保存",
            cancelButtonText: "不保存",
            type: "error",
          },
        );
      } catch {
        return;
      }
    } else if (metadata.storedBytes === 0) {
      try {
        await ElMessageBox.confirm(
          "服务端明确返回 0 字节脱敏日志。空文件不构成执行成功证据，是否仍要保存？",
          "下载空日志",
          {
            confirmButtonText: "保存空文件",
            cancelButtonText: "不保存",
            type: "warning",
          },
        );
      } catch {
        return;
      }
    }

    saveBlob(artifact.blob, metadata.filename);
    ElMessage.success(
      metadata.incomplete
        ? "已保存服务端明确标记为不完整的脱敏日志。"
        : "脱敏日志已通过响应哈希校验并保存。",
    );
  } catch (caught) {
    logDownloadError.value = caught;
  } finally {
    logDownloading.value = false;
  }
}

function parseLogDownloadMetadata(
  headers: Headers,
  blob: Blob,
): LogDownloadMetadata {
  const contentType = headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().startsWith("text/plain")) {
    throw new Error(
      "日志下载响应不是契约要求的 text/plain，文件未保存。",
    );
  }
  const contentDisposition = requiredHeader(
    headers,
    "Content-Disposition",
  );
  const metadata: LogDownloadMetadata = {
    filename: filenameFromContentDisposition(contentDisposition),
    redactionRulesVersion: requiredHeader(
      headers,
      "X-Log-Redaction-Version",
    ),
    contentSha256: requiredHeader(headers, "X-Content-SHA256"),
    truncated: booleanHeader(headers, "X-Log-Truncated"),
    incomplete: booleanHeader(headers, "X-Log-Incomplete"),
    rawReceivedBytes: integerHeader(
      headers,
      "X-Log-Raw-Received-Bytes",
    ),
    redactedReceivedBytes: integerHeader(
      headers,
      "X-Log-Redacted-Received-Bytes",
    ),
    storedBytes: integerHeader(headers, "X-Log-Stored-Bytes"),
    droppedBytes: integerHeader(headers, "X-Log-Dropped-Bytes"),
    gapCount: integerHeader(headers, "X-Log-Gap-Count"),
    truncationReason: truncationReasonHeader(headers),
  };
  if (
    metadata.redactionRulesVersion.length > 32 ||
    !/^[a-f0-9]{64}$/.test(metadata.contentSha256) ||
    metadata.storedBytes !== blob.size ||
    metadata.redactedReceivedBytes !==
      metadata.storedBytes + metadata.droppedBytes ||
    metadata.incomplete !== (metadata.gapCount > 0) ||
    metadata.truncated !==
      (metadata.truncationReason !== "NONE")
  ) {
    throw new Error(
      "日志下载响应头、正文大小或缺口记账互相矛盾，文件未保存。",
    );
  }
  return metadata;
}

function requiredHeader(headers: Headers, name: string): string {
  const value = headers.get(name)?.trim();
  if (!value) {
    throw new Error(`日志下载缺少 ${name} 响应头，文件未保存。`);
  }
  return value;
}

function booleanHeader(headers: Headers, name: string): boolean {
  const value = requiredHeader(headers, name);
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`日志下载 ${name} 不是 true/false，文件未保存。`);
}

function integerHeader(headers: Headers, name: string): number {
  const value = requiredHeader(headers, name);
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`日志下载 ${name} 不是非负整数，文件未保存。`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`日志下载 ${name} 超出安全整数范围，文件未保存。`);
  }
  return parsed;
}

function truncationReasonHeader(headers: Headers): LogTruncationReason {
  const value = requiredHeader(
    headers,
    "X-Log-Truncation-Reason",
  );
  if (
    value === "NONE" ||
    value === "EXECUTION_LIMIT" ||
    value === "LINE_LIMIT" ||
    value === "RING_EVICTION"
  ) {
    return value;
  }
  throw new Error(
    "日志下载 X-Log-Truncation-Reason 不在契约枚举中，文件未保存。",
  );
}

function filenameFromContentDisposition(value: string): string {
  if (!/^attachment(?:;|$)/i.test(value.trim())) {
    throw new Error(
      "日志下载 Content-Disposition 不是 attachment，文件未保存。",
    );
  }
  const extended = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(value);
  const quoted = /filename\s*=\s*"([^"]+)"/i.exec(value);
  const unquoted = /filename\s*=\s*([^;\s]+)/i.exec(value);
  const encoded = (
    extended?.[1] ??
    quoted?.[1] ??
    unquoted?.[1] ??
    ""
  ).trim();
  if (!encoded) {
    throw new Error(
      "日志下载 Content-Disposition 未提供文件名，文件未保存。",
    );
  }
  let decoded: string;
  try {
    decoded = extended ? decodeURIComponent(encoded) : encoded;
  } catch {
    throw new Error(
      "日志下载 Content-Disposition 文件名编码无效，文件未保存。",
    );
  }
  const filename = decoded
    .split(/[\\/]/)
    .pop()
    ?.replace(/[\u0000-\u001f\u007f]/g, "_")
    .trim();
  if (!filename || filename === "." || filename === "..") {
    throw new Error(
      "日志下载 Content-Disposition 文件名不安全，文件未保存。",
    );
  }
  return filename.slice(0, 180);
}

async function sha256Hex(blob: Blob): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    await blob.arrayBuffer(),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function logGapReasonLabel(reason: LogGap["reason"]): string {
  const labels: Record<LogGap["reason"], string> = {
    LINE_LIMIT: "单行超过上限，正文已截断",
    EXECUTION_LIMIT: "本次执行日志超过存储上限",
    RING_EVICTION: "有界缓冲区淘汰了较早日志",
    SOURCE_READ_ERROR: "读取 DataX 输出失败",
    DECODE_ERROR: "日志不是可安全解码的 UTF-8",
    REDACTION_FAILURE: "脱敏失败，原文未保存",
    STORAGE_FAILURE: "存储正文校验失败或疑似被替换/篡改",
    FENCE_LOST: "Worker 丢失 fencing 所有权",
  };
  return labels[reason];
}

function logGapRange(gap: LogGap): string {
  if (gap.after_sequence === null && gap.before_sequence === null)
    return "序号边界未知";
  return `位于序号 ${gap.after_sequence ?? "起点"} 之后、${gap.before_sequence ?? "末尾"} 之前`;
}

function truncationReasonLabel(reason: LogTruncationReason): string {
  const labels: Record<LogTruncationReason, string> = {
    NONE: "无容量截断",
    EXECUTION_LIMIT: "执行总量上限",
    LINE_LIMIT: "单行上限",
    RING_EVICTION: "缓冲区淘汰",
  };
  return labels[reason];
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024)
    return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function startRefresh(): void {
  if (refreshTimer !== undefined) window.clearInterval(refreshTimer);
  refreshTimer = window.setInterval(() => {
    if (document.visibilityState === "visible") void load(true);
  }, 5000);
}

onMounted(() => {
  void load();
  void loadJobs();
  startRefresh();
});

onBeforeUnmount(() => {
  if (refreshTimer !== undefined) window.clearInterval(refreshTimer);
  stopLogAutoRefresh();
});

watch(() => props.projectId, () => {
  void load();
  void loadJobs();
});
watch(
  () => detailVisible.value,
  (visible) => {
    if (!visible) stopLogAutoRefresh();
  },
);
watch(
  () => [
    runForm.jobId,
    runForm.versionId,
    runForm.sourceConfirmed,
    runForm.sourceNote,
    runForm.targetConfirmed,
    runForm.responsibleParty,
    runForm.validUntil,
    runForm.targetNote,
  ],
  () => {
    if (runVisible.value && !actionLoading.value) {
      runIdempotencyKey.value = newIdempotencyKey();
      runOutcomeUncertain.value = false;
      runRequestSnapshot.value = null;
    }
  },
);
watch(
  () => [revokeForm.reason, revokeForm.note],
  () => {
    if (revokeVisible.value && !actionLoading.value) {
      revokeIdempotencyKey.value = newIdempotencyKey();
      revokeReportedAt.value = new Date().toISOString();
    }
  },
);
watch(
  () => [
    remediationForm.action,
    remediationForm.cleanupPerformed,
    remediationForm.reason,
  ],
  () => {
    if (remediationVisible.value && !actionLoading.value) {
      remediationIdempotencyKey.value = newIdempotencyKey();
      remediationConfirmedAt.value = new Date().toISOString();
    }
  },
);
watch(
  () => props.requestedJobId,
  (jobId) => {
    if (jobId) {
      void openRun(jobId);
      emit("requestConsumed");
    }
  },
  { immediate: true },
);
watch(
  () => props.requestedExecutionId,
  (executionId) => {
    if (executionId) {
      void openDetail(executionId);
      emit("requestConsumed");
    }
  },
  { immediate: true },
);
</script>

<template>
  <div class="page-stack">
    <header class="page-header">
      <div>
        <p class="kicker">人工运行与核验</p>
        <h1>运行中心</h1>
        <p>进程状态、目标数据影响和独立核验结果始终分开展示。</p>
      </div>
      <el-tooltip
        :disabled="workerReady"
        content="Worker/Runtime/oracle 尚未全部就绪，后端必须阻断新运行。"
      >
        <span>
          <el-button
            v-if="canOperate"
            type="primary"
            :disabled="!workerReady"
            @click="openRun()"
          >
            手动运行已发布版本
          </el-button>
        </span>
      </el-tooltip>
    </header>

    <el-alert
      v-if="!workerReady"
      type="warning"
      :closable="false"
      show-icon
      title="当前不能提交新执行"
      description="历史记录仍可查看；Worker、固定 Runtime、独立 oracle 或恢复对账尚未就绪。"
    />
    <section class="filter-bar">
      <el-input
        v-model="filters.query"
        clearable
        placeholder="执行编号或任务名"
        @keyup.enter="load()"
      />
      <el-select v-model="filters.processState" clearable placeholder="全部进程状态" @change="load()">
        <el-option label="排队中" value="QUEUED" />
        <el-option label="启动中" value="STARTING" />
        <el-option label="运行中" value="RUNNING" />
        <el-option label="核验中" value="VERIFYING" />
        <el-option label="复制已核验成功" value="SUCCEEDED" />
        <el-option label="失败" value="FAILED" />
        <el-option label="已超时" value="TIMED_OUT" />
        <el-option label="取消请求中" value="CANCEL_REQUESTED" />
        <el-option label="已取消" value="CANCELED" />
        <el-option label="状态丢失" value="LOST" />
      </el-select>
      <el-select
        v-model="filters.dataEffect"
        clearable
        placeholder="全部数据影响"
        @change="load()"
      >
        <el-option label="确认无影响" value="NONE" />
        <el-option label="可能有影响" value="POSSIBLE" />
        <el-option label="影响已测得" value="CONFIRMED" />
        <el-option label="影响未知" value="UNKNOWN" />
      </el-select>
      <el-select
        v-model="filters.verificationState"
        clearable
        placeholder="全部核验状态"
        @change="load()"
      >
        <el-option label="尚未核验" value="NOT_STARTED" />
        <el-option label="核验中" value="VERIFYING" />
        <el-option label="核验通过" value="PASSED" />
        <el-option label="核验不一致" value="FAILED" />
        <el-option label="核验无结论" value="INCONCLUSIVE" />
      </el-select>
      <el-select
        v-model="filters.targetExclusivityStatus"
        clearable
        placeholder="全部目标独占状态"
        @change="load()"
      >
        <el-option label="有效" value="ACTIVE" />
        <el-option label="已撤回" value="REVOKED" />
        <el-option label="已过期" value="EXPIRED" />
      </el-select>
      <el-select v-model="filters.jobId" clearable filterable placeholder="全部任务" @change="load()">
        <el-option
          v-for="job in jobs"
          :key="job.id"
          :label="job.name"
          :value="job.id"
        />
      </el-select>
      <el-input
        v-model="filters.jobVersionId"
        clearable
        placeholder="JobVersion UUID"
        @keyup.enter="load()"
      />
      <el-input
        v-model="filters.requestedBy"
        clearable
        placeholder="触发人 UUID"
        @keyup.enter="load()"
      />
      <el-input v-model="filters.from" type="datetime-local" aria-label="排队时间起点" />
      <el-input v-model="filters.to" type="datetime-local" aria-label="排队时间终点" />
      <el-select v-model="filters.rerun" clearable placeholder="首次/恢复后执行" @change="load()">
        <el-option label="首次执行" value="false" />
        <el-option label="恢复后再次执行" value="true" />
      </el-select>
      <el-button :loading="loading" @click="load()">筛选</el-button>
      <el-button @click="resetFilters">重置</el-button>
    </section>

    <ProblemPanel v-if="error" :error="error" @retry="load()" />
    <el-skeleton v-if="loading && !items.length" :rows="7" animated />
    <EmptyState
      v-else-if="!items.length && !error"
      title="当前筛选范围没有执行"
      description="页面不会填充演示执行。发布真实任务后，由 Admin 或 Operator 人工提交一次性复制。"
    />

    <section v-else class="content-card">
      <el-table :data="items" row-key="id">
        <el-table-column label="执行编号" min-width="150">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row.id)">{{ shortId(row.id) }}</el-button>
          </template>
        </el-table-column>
        <el-table-column label="任务 / 版本" min-width="210">
          <template #default="{ row }">
            <div class="primary-cell">
              <strong>{{ jobName(row.job_id) }}</strong>
              <span>版本 {{ shortId(row.job_version_id) }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="进程状态" min-width="165">
          <template #default="{ row }"><StateBadge :value="row.process_state" kind="process" /></template>
        </el-table-column>
        <el-table-column label="数据影响" min-width="155">
          <template #default="{ row }"><StateBadge :value="row.data_effect" kind="effect" /></template>
        </el-table-column>
        <el-table-column label="独立核验" min-width="145">
          <template #default="{ row }"><StateBadge :value="row.verification_state" kind="verification" /></template>
        </el-table-column>
        <el-table-column label="目标独占" min-width="145">
          <template #default="{ row }"><StateBadge :value="row.target_exclusivity_status" kind="exclusivity" /></template>
        </el-table-column>
        <el-table-column label="触发人" min-width="150">
          <template #default="{ row }"><code>{{ shortId(row.requested_by) }}</code></template>
        </el-table-column>
        <el-table-column label="执行来源" min-width="145">
          <template #default="{ row }">
            {{ row.rerun_of_execution_id ? "恢复后再次执行" : "首次执行" }}
          </template>
        </el-table-column>
        <el-table-column label="排队时间" min-width="180">
          <template #default="{ row }">{{ formatTime(row.queued_at) }}</template>
        </el-table-column>
        <el-table-column label="结束时间" min-width="180">
          <template #default="{ row }">{{ formatTime(row.finished_at) }}</template>
        </el-table-column>
      </el-table>
      <div v-if="hasMore" class="load-more">
        <el-button :loading="loadingMore" @click="load(false, true)">加载下一页</el-button>
      </div>
    </section>

    <el-dialog v-model="runVisible" title="运行前确认" width="min(760px, 96vw)" destroy-on-close>
      <ProblemPanel v-if="error" :error="error" :show-retry="false" />
      <el-alert
        v-if="runOutcomeUncertain"
        type="warning"
        :closable="false"
        show-icon
        title="提交结果待确认"
        description="请勿关闭对话框或创建新意图。再次点击提交会复用同一个 Idempotency-Key，由后端返回原执行或处理中状态。"
      />
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="取消不能回滚已提交数据"
        description="这是 insert-only 的一次性全表复制。DataX 退出 0 后仍须独立 oracle 核验。"
      />
      <el-form label-position="top">
        <el-form-item label="复制任务" required>
          <el-select v-model="runForm.jobId" class="full-width" @change="jobChanged">
            <el-option
              v-for="job in jobs.filter((item) => item.latest_published_version_id && item.status !== 'ARCHIVED')"
              :key="job.id"
              :label="job.name"
              :value="job.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="不可变 JobVersion" required>
          <el-select
            v-model="runForm.versionId"
            class="full-width"
            :loading="versionsLoading"
            :disabled="!runForm.jobId"
          >
            <el-option
              v-for="version in versions"
              :key="version.id"
              :label="`v${version.version_no} · ${version.spec_hash.slice(0, 12)}…`"
              :value="version.id"
            />
          </el-select>
          <span class="field-help">
            当前选择：{{ selectedRunJob?.name || "未选择" }}。执行不会自动选择未来的新版本。
          </span>
        </el-form-item>

        <section class="confirmation-box">
          <el-checkbox v-model="runForm.sourceConfirmed">
            我已确认源表停止写入，并会从运行前检查保持静默到独立 oracle 完成
          </el-checkbox>
          <el-input
            v-model="runForm.sourceNote"
            type="textarea"
            maxlength="500"
            placeholder="可选非敏感说明"
          />
        </section>

        <section class="confirmation-box">
          <el-checkbox v-model="runForm.targetConfirmed">
            我已与目标所有者确认独占窗口，并理解平台锁不能阻止外部系统写入
          </el-checkbox>
          <div class="form-grid form-grid--two">
            <el-form-item label='声明版本'>
              <el-input model-value="1.0" disabled />
            </el-form-item>
            <el-form-item label="责任主体" required>
              <el-select v-model="runForm.responsibleParty" class="full-width">
                <el-option label="Operator" value="OPERATOR" />
                <el-option label="DBA" value="DBA" />
              </el-select>
            </el-form-item>
          </div>
          <el-form-item label="有效截止时间" required>
            <el-input v-model="runForm.validUntil" type="datetime-local" />
            <span class="field-help">必须覆盖预计执行时间和目标一致性核验快照读完时间。</span>
          </el-form-item>
          <el-input
            v-model="runForm.targetNote"
            type="textarea"
            maxlength="500"
            placeholder="可选非敏感说明"
          />
        </section>
        <p class="field-help">
          人工声明不是技术锁，也不能证明未报告或已回滚的外部 DML/DDL 从未发生。知悉窗口破坏时必须立即报告。
        </p>
      </el-form>
      <template #footer>
        <el-button @click="runVisible = false">取消</el-button>
        <el-button type="primary" :disabled="!canSubmitRun" :loading="actionLoading" @click="submitRun">
          确认并提交执行
        </el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="detailVisible" title="执行详情" size="min(980px, 98vw)">
      <ProblemPanel v-if="detailError" :error="detailError" :show-retry="false" />
      <el-skeleton v-if="detailLoading" :rows="10" animated />
      <div v-else-if="detail" class="page-stack">
        <section class="execution-hero">
          <div>
            <span class="kicker">执行 {{ shortId(detail.id) }}</span>
            <h2>{{ detail.process_state === "SUCCEEDED" ? "复制已核验成功" : "执行事实详情" }}</h2>
          </div>
          <div class="inline-actions">
            <el-button
              v-if="canOperate && cancellableStates.has(detail.process_state) && detail.process_state !== 'CANCEL_REQUESTED'"
              type="danger"
              plain
              :loading="actionLoading"
              @click="requestCancel"
            >
              请求取消
            </el-button>
            <el-button
              v-if="
                canOperate &&
                detail.target_exclusivity_status === 'ACTIVE' &&
                !terminalStates.has(detail.process_state)
              "
              type="warning"
              plain
              @click="openRevoke"
            >
              报告独占窗口破坏
            </el-button>
          </div>
        </section>

        <section class="state-triptych">
          <article><span>进程状态</span><StateBadge :value="detail.process_state" kind="process" /></article>
          <article><span>数据影响</span><StateBadge :value="detail.data_effect" kind="effect" /></article>
          <article><span>独立核验</span><StateBadge :value="detail.verification_state" kind="verification" /></article>
        </section>

        <el-alert
          v-if="detail.process_state === 'VERIFYING'"
          type="warning"
          :closable="false"
          show-icon
          title="DataX 进程已结束，正在独立核验"
          description="此时不能显示复制成功；只有 oracle PASSED 才能形成业务成功。"
        />
        <el-alert
          v-if="['POSSIBLE', 'UNKNOWN'].includes(detail.data_effect)"
          type="error"
          :closable="false"
          show-icon
          title="目标可能已写入"
          description="平台不会自动清理业务表。恢复前必须如实处置并通过独立 RecoveryProbe 空表复检。"
        />
        <el-alert
          v-if="detail.log_incomplete"
          type="error"
          :closable="false"
          show-icon
          title="脱敏后的原序日志不完整"
          :description="`已有 ${detail.log_dropped_bytes} 字节未保存；执行状态不从日志猜测。`"
        />

        <section class="content-card">
          <h3>目标外部独占声明</h3>
          <dl class="detail-list">
            <div><dt>状态</dt><dd><StateBadge :value="detail.target_exclusivity_status" kind="exclusivity" /></dd></div>
            <div><dt>声明版本</dt><dd>{{ detail.target_exclusivity_confirmation.statement_version }}</dd></div>
            <div><dt>责任主体</dt><dd>{{ detail.target_exclusivity_confirmation.responsible_party }}</dd></div>
            <div><dt>确认时间</dt><dd>{{ formatTime(detail.target_exclusivity_confirmation.confirmed_at) }}</dd></div>
            <div><dt>有效截止</dt><dd>{{ formatTime(detail.target_exclusivity_confirmation.valid_until) }}</dd></div>
            <div><dt>撤回/过期时间</dt><dd>{{ formatTime(detail.target_exclusivity_revoked_at) }}</dd></div>
            <div><dt>原因</dt><dd><code>{{ detail.target_exclusivity_revocation_reason ?? "—" }}</code></dd></div>
          </dl>
          <p class="field-help">
            这是带报告义务的人工前提，不是数据库锁。平台无法检测全部未报告或已回滚的外部写入。
          </p>
        </section>

        <section class="content-card">
          <h3>时间与错误</h3>
          <dl class="detail-list">
            <div><dt>排队</dt><dd>{{ formatTime(detail.queued_at) }}</dd></div>
            <div><dt>开始</dt><dd>{{ formatTime(detail.started_at) }}</dd></div>
            <div><dt>结束</dt><dd>{{ formatTime(detail.finished_at) }}</dd></div>
            <div><dt>DataX 退出码</dt><dd>{{ detail.exit_code ?? "未采集" }}</dd></div>
            <div><dt>失败码</dt><dd><code>{{ detail.failure_code ?? "—" }}</code></dd></div>
            <div><dt>安全摘要</dt><dd>{{ detail.failure_message ?? "—" }}</dd></div>
            <div><dt>目标锁</dt><dd>{{ detail.target_copy_lock.state }}</dd></div>
          </dl>
        </section>

        <section v-if="canOperate && recoverableStates.has(detail.process_state)" class="content-card">
          <div class="section-heading">
            <div><span class="kicker">故障闭环</span><h3>恢复门禁</h3></div>
            <el-button @click="loadRecovery">读取真实门禁</el-button>
          </div>
          <ProblemPanel v-if="recoveryError" :error="recoveryError" :show-retry="false" />
          <template v-if="recovery">
            <dl class="detail-list">
              <div><dt>状态</dt><dd><StateBadge :value="recovery.status" /></dd></div>
              <div><dt>目标数据影响</dt><dd><StateBadge :value="recovery.data_effect_at_open" kind="effect" /></dd></div>
              <div><dt>处置提交时间</dt><dd>{{ formatTime(recovery.submitted_at) }}</dd></div>
              <div><dt>空表复检通过时间</dt><dd>{{ formatTime(recovery.verified_at) }}</dd></div>
              <div><dt>原因</dt><dd><code>{{ recovery.reason_code ?? "—" }}</code></dd></div>
            </dl>
            <div class="inline-actions">
              <el-button
                v-if="recovery.status !== 'VERIFIED'"
                type="primary"
                plain
                @click="openRemediation"
              >
                提交外部处置确认
              </el-button>
              <el-button
                v-if="recovery.status === 'VERIFIED'"
                type="primary"
                :loading="actionLoading"
                @click="submitRerun"
              >
                恢复后再次执行
              </el-button>
            </div>
          </template>
          <p v-else class="muted">先读取门禁；不能只依据 CANCELED 或 data_effect 推断可以再次执行。</p>
        </section>

        <section class="content-card">
          <div class="section-heading">
            <div>
              <span class="kicker">服务端脱敏 · 原序分页</span>
              <h3>运行日志</h3>
            </div>
            <div class="inline-actions log-actions">
              <el-input
                v-model="logSearch"
                clearable
                placeholder="仅搜索已加载内容"
              />
              <el-button
                v-if="!terminalStates.has(detail.process_state)"
                :disabled="logAutoRefreshActive"
                @click="startLogAutoRefresh"
              >
                {{
                  logAutoRefreshActive
                    ? `自动刷新 ${logAutoRefreshPolls}/${LOG_AUTO_REFRESH_MAX_POLLS}`
                    : "自动刷新约 60 秒"
                }}
              </el-button>
              <el-button
                :loading="logsLoading"
                @click="loadLogs(!logsLoaded || !!logIntegrityError)"
              >
                {{
                  logIntegrityError
                    ? "从头重新核对"
                    : !logsLoaded
                    ? "读取日志"
                    : logsEof
                      ? "检查新日志"
                      : "加载下一页"
                }}
              </el-button>
              <el-button
                type="primary"
                plain
                :loading="logDownloading"
                @click="downloadLogs"
              >
                下载脱敏日志
              </el-button>
            </div>
          </div>
          <ProblemPanel v-if="logsError" :error="logsError" :show-retry="false" />
          <ProblemPanel
            v-if="logIntegrityError"
            :error="logIntegrityError"
            title="日志完整性检查失败"
            :show-retry="false"
          />
          <ProblemPanel
            v-if="logDownloadError"
            :error="logDownloadError"
            title="日志下载未完成"
            :show-retry="false"
          />
          <el-alert
            v-if="logAutoRefreshLimitReached"
            type="warning"
            :closable="false"
            show-icon
            title="有限自动刷新已停止"
            :description="`已完成 ${LOG_AUTO_REFRESH_MAX_POLLS} 次检查（约 60 秒），不会在后台无限轮询。可手动检查或再次启动一轮。`"
          />
          <el-alert
            v-if="logsIncomplete"
            type="error"
            :closable="false"
            show-icon
            title="服务端报告日志存在缺口、截断或安全失败"
            :description="
              logSnapshot
                ? `缺口 ${logSnapshot.gap_count} 个，丢弃 ${formatBytes(logSnapshot.dropped_bytes)}，容量截断原因：${truncationReasonLabel(logSnapshot.reason)}。cursor 与下载都不能恢复缺失内容。`
                : '执行摘要已标记日志不完整；读取分页事实后可查看详细原因。'
            "
          />
          <el-alert
            v-if="
              logsLoaded &&
              !logsIncomplete &&
              !logs.length &&
              terminalStates.has(detail.process_state)
            "
            type="warning"
            :closable="false"
            show-icon
            title="服务端明确返回 0 字节日志"
            description="空日志不是执行成功证据；进程状态、数据影响和独立核验仍以各自事实为准。"
          />
          <el-alert
            v-if="logDownloadMeta"
            :type="logDownloadMeta.incomplete ? 'error' : 'success'"
            :closable="false"
            show-icon
            :title="
              logDownloadMeta.incomplete
                ? '最近一次下载被服务端标记为不完整'
                : '最近一次下载正文哈希已核对'
            "
            :description="
              `${logDownloadMeta.filename} · ${formatBytes(logDownloadMeta.storedBytes)} · SHA-256 ${logDownloadMeta.contentSha256.slice(0, 12)}… · 脱敏规则 ${logDownloadMeta.redactionRulesVersion}。此校验不代表执行成功。`
            "
          />

          <dl v-if="logSnapshot" class="log-facts">
            <div>
              <dt>脱敏规则</dt>
              <dd><code>{{ logSnapshot.redaction_rules_version }}</code></dd>
            </div>
            <div>
              <dt>脱敏前仅计数</dt>
              <dd>{{ formatBytes(logSnapshot.raw_received_bytes) }}</dd>
            </div>
            <div>
              <dt>脱敏后接收</dt>
              <dd>{{ formatBytes(logSnapshot.redacted_received_bytes) }}</dd>
            </div>
            <div>
              <dt>实际持久化</dt>
              <dd>{{ formatBytes(logSnapshot.stored_bytes) }}</dd>
            </div>
            <div>
              <dt>未保存</dt>
              <dd>{{ formatBytes(logSnapshot.dropped_bytes) }}</dd>
            </div>
            <div>
              <dt>正文保留至</dt>
              <dd>{{ formatTime(logSnapshot.expires_at) }}</dd>
            </div>
          </dl>

          <div
            v-if="logSnapshot?.gaps.length"
            class="log-gap-list"
            aria-label="日志缺口"
          >
            <article
              v-for="gap in logSnapshot.gaps"
              :key="`${gap.gap_no}-${gap.evidence_hash}`"
              class="log-gap-card"
            >
              <div>
                <strong>缺口 {{ gap.gap_no }}：{{ logGapReasonLabel(gap.reason) }}</strong>
                <span>{{ logGapRange(gap) }} · 检测于 {{ formatTime(gap.detected_at) }}</span>
              </div>
              <p>
                丢弃 {{ formatBytes(gap.dropped_bytes) }} · 脱敏后接收
                {{ formatBytes(gap.redacted_received_bytes) }} · 实际保存
                {{ formatBytes(gap.stored_bytes) }}
              </p>
              <el-tooltip :content="gap.evidence_hash">
                <code>evidence {{ gap.evidence_hash.slice(0, 12) }}…</code>
              </el-tooltip>
            </article>
          </div>

          <el-skeleton
            v-if="logsLoading && !logsLoaded"
            :rows="4"
            animated
          />
          <div v-if="filteredLogs.length" class="log-viewer" role="log" aria-label="脱敏运行日志">
            <div
              v-for="line in filteredLogs"
              :key="line.sequence"
              class="log-line"
              :class="{ 'log-line--truncated': line.line_truncated }"
            >
              <span>{{ line.sequence }}</span>
              <time>{{ formatTime(line.timestamp) }}</time>
              <span>{{ line.stream }}</span>
              <strong :class="`log-level--${line.level.toLowerCase()}`">{{ line.level }}</strong>
              <div class="log-line__body">
                <pre>{{ line.message }}</pre>
                <strong v-if="line.line_truncated" class="log-line__warning">
                  本行已截断，未保存 {{ formatBytes(line.dropped_bytes) }}
                </strong>
              </div>
            </div>
          </div>
          <EmptyState
            v-else-if="
              logs.length &&
              logSearch.trim() &&
              !logsError &&
              !logIntegrityError
            "
            title="已加载范围内没有匹配内容"
            description="搜索不会访问未加载页；可继续分页后再查找。"
          />
          <EmptyState
            v-else-if="!logsError && !logIntegrityError && !logsLoading"
            :title="logEmptyTitle"
            :description="logEmptyDescription"
          />
          <p v-if="logsLoaded" class="muted">
            已加载 {{ logs.length }} 行；搜索只覆盖已加载内容；当前页游标
            {{ logsEof ? "已到当前末尾，仍可检查新日志" : "还有下一页" }}。
            自动刷新最多 {{ LOG_AUTO_REFRESH_MAX_POLLS }} 次，不会后台无限运行。
          </p>
        </section>
      </div>
    </el-drawer>

    <el-dialog v-model="revokeVisible" title="撤回 / 报告目标独占窗口破坏" width="min(620px, 96vw)">
      <el-alert
        type="error"
        :closable="false"
        show-icon
        title="提交后本次执行不能成为核验成功"
        description="未领取执行将由 reconciler 取消；已领取执行由 Worker 停止并进入恢复门禁。"
      />
      <el-form label-position="top">
        <el-form-item label="原因" required>
          <el-select v-model="revokeForm.reason" class="full-width">
            <el-option label="Operator 撤回承诺" value="OPERATOR_REVOKED" />
            <el-option label="DBA 撤回承诺" value="DBA_REVOKED" />
            <el-option label="已报告平台外 DML/DDL" value="EXTERNAL_DML_DDL_REPORTED" />
            <el-option label="变更冻结已破坏" value="CHANGE_FREEZE_BROKEN" />
          </el-select>
        </el-form-item>
        <el-form-item label="非敏感说明">
          <el-input v-model="revokeForm.note" type="textarea" maxlength="500" show-word-limit />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="revokeVisible = false">取消</el-button>
        <el-button type="danger" :loading="actionLoading" @click="submitRevoke">确认并立即报告</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="remediationVisible" title="提交外部处置确认" width="min(680px, 96vw)">
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="确认不能代替平台空表复检"
        description="请在目标数据库外部完成必要处置；平台不会执行 truncate、delete、drop 或建表。"
      />
      <el-form label-position="top">
        <el-form-item label="处置方式" required>
          <el-select v-model="remediationForm.action" class="full-width" @change="remediationActionChanged">
            <el-option label="已清理目标表" value="CLEANED_TARGET" />
            <el-option label="已重建目标表" value="RECREATED_TARGET" />
            <el-option label="经判断无需清理" value="NO_CLEANUP_REQUIRED" />
            <el-option label="其他外部处置" value="OTHER_EXTERNAL_ACTION" />
          </el-select>
        </el-form-item>
        <el-form-item label="是否实际执行清理" required>
          <el-switch
            v-model="remediationForm.cleanupPerformed"
            :disabled="remediationForm.action !== 'OTHER_EXTERNAL_ACTION'"
            active-text="是"
            inactive-text="否"
          />
        </el-form-item>
        <el-form-item label="事实理由" required>
          <el-input
            v-model="remediationForm.reason"
            type="textarea"
            maxlength="1000"
            show-word-limit
            placeholder="如实说明实际处置或为什么无需清理；不要填写 SQL、密码或数据转储"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="remediationVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="actionLoading"
          :disabled="!remediationForm.reason.trim()"
          @click="submitRemediationForm"
        >
          提交并排队 RecoveryProbe
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>
