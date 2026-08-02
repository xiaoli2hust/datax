import type { AuthResponse, FieldError, Problem } from "../types";

const API_BASE = "/api/v1";

let accessToken: string | null = null;
let refreshPromise: Promise<AuthResponse> | null = null;

export class ApiError extends Error {
  readonly problem: Problem;
  /**
   * A bounded delta-seconds value from a failed response's `Retry-After`
   * header.  It deliberately does not retain the raw header or a response
   * object, so views can offer human guidance without treating a failed
   * request as something safe to replay.
   */
  readonly retryAfterSeconds: number | null;

  constructor(problem: Problem, retryAfterSeconds: number | null = null) {
    super(problem.title);
    this.name = "ApiError";
    this.problem = problem;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  idempotencyKey?: string;
  ifMatch?: string;
  signal?: AbortSignal;
  allowRefresh?: boolean;
  acceptedStatuses?: number[];
}

export interface ApiDownloadResponse {
  blob: Blob;
  headers: Headers;
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function clearAccessToken(): void {
  accessToken = null;
}

export function newIdempotencyKey(): string {
  return `des-ui:${crypto.randomUUID()}`;
}

export function weakEtag(rowVersion: number): string {
  return `W/"${rowVersion}"`;
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

export function isEndpointUnavailable(value: unknown): boolean {
  return isApiError(value) && value.problem.code === "ENDPOINT_NOT_IMPLEMENTED";
}

/**
 * These responses are explicitly retryable at the product level, but never
 * safe for a client-side replay.  The original external operation may have
 * used a short-lived credential, grant, policy, cursor, or draft snapshot.
 * A user must wait/refresh as appropriate and deliberately initiate it again.
 */
export function requiresManualDatasourceOperationRetry(
  problem: Pick<Problem, "code"> | null | undefined,
): boolean {
  return (
    problem?.code === "DATASOURCE_OPERATION_ADMISSION_LIMITED" ||
    problem?.code === "DATASOURCE_OPERATION_STALE" ||
    problem?.code === "DATASOURCE_OPERATION_DEADLINE_EXCEEDED"
  );
}

export function datasourceOperationManualRetryGuidance(
  problem: Pick<Problem, "code"> | null | undefined,
  retryAfter: number | null,
): string | null {
  if (problem?.code === "DATASOURCE_OPERATION_ADMISSION_LIMITED") {
    const wait = retryAfter === null ? "请稍后" : `请至少等待约 ${retryAfter} 秒后`;
    return `${wait}从原操作按钮手动重试。页面不会自动重放这次数据库外部操作。`;
  }
  if (problem?.code === "DATASOURCE_OPERATION_STALE") {
    return "连接配置、凭据、权限、元数据范围或任务草稿可能已变化。请刷新相关信息后，从原操作按钮手动重试；页面不会自动重放旧请求。";
  }
  if (problem?.code === "DATASOURCE_OPERATION_DEADLINE_EXCEEDED") {
    return "本次数据库外部操作已超过总时限，未采用这次结果。请确认目标可达后，从原操作按钮手动重试；页面不会自动重放旧请求。";
  }
  return null;
}

function canReplay(method: string, idempotencyKey?: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS" || idempotencyKey !== undefined;
}

function isProblem(payload: unknown): payload is Partial<Problem> {
  return (
    typeof payload === "object" &&
    payload !== null &&
    "code" in payload &&
    typeof (payload as { code?: unknown }).code === "string"
  );
}

function normalizedProblem(
  response: Response,
  payload: unknown,
  path: string,
): Problem {
  const requestId = response.headers.get("X-Request-Id");
  if (isProblem(payload)) {
    const raw = payload as Partial<Problem>;
    return {
      type: raw.type ?? "about:blank",
      title: raw.title ?? "请求未完成",
      status: raw.status ?? response.status,
      code: raw.code ?? "UNKNOWN_ERROR",
      detail: raw.detail ?? null,
      instance: raw.instance ?? path,
      request_id: raw.request_id ?? requestId,
      retryable: raw.retryable ?? false,
      field_errors: Array.isArray(raw.field_errors) ? (raw.field_errors as FieldError[]) : [],
      details: raw.details ?? null,
    };
  }

  if ([404, 405, 501].includes(response.status)) {
    return {
      type: "https://datax-enterprise-studio.local/problems/endpoint-not-implemented",
      title: "后端尚未实现此功能",
      status: response.status,
      code: "ENDPOINT_NOT_IMPLEMENTED",
      detail: `当前本机后端没有提供 ${path}。界面不会用演示数据代替真实结果。`,
      instance: path,
      request_id: requestId,
      retryable: false,
      field_errors: [],
    };
  }

  return {
    type: "about:blank",
    title: response.status >= 500 ? "本机服务暂时不可用" : "请求未完成",
    status: response.status,
    code: `HTTP_${response.status}`,
    detail: "服务返回了不符合 Problem JSON 契约的错误响应。",
    instance: path,
    request_id: requestId,
    retryable: response.status >= 500,
    field_errors: [],
  };
}

function retryAfterSeconds(response: Response): number | null {
  const raw = response.headers.get("Retry-After")?.trim();
  // The API emits delta-seconds.  Do not parse HTTP dates: using the client's
  // clock for an admission-control decision would produce misleading advice.
  if (!raw || !/^\d{1,4}$/.test(raw)) return null;
  const seconds = Number(raw);
  // Bound untrusted header input before it reaches a user-visible message.
  return Number.isSafeInteger(seconds) && seconds > 0 && seconds <= 3_600 ? seconds : null;
}

async function readPayload(response: Response): Promise<unknown> {
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("json")) return null;
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function refreshAccessToken(): Promise<AuthResponse> {
  if (refreshPromise !== null) return refreshPromise;
  refreshPromise = (async () => {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "X-Request-Id": crypto.randomUUID(),
      },
    });
    const payload = await readPayload(response);
    if (!response.ok) {
      clearAccessToken();
      throw new ApiError(
        normalizedProblem(response, payload, "/auth/refresh"),
        retryAfterSeconds(response),
      );
    }
    const auth = payload as AuthResponse;
    setAccessToken(auth.access_token);
    return auth;
  })().finally(() => {
    refreshPromise = null;
  });
  return refreshPromise;
}

export async function restoreSessionToken(): Promise<AuthResponse> {
  return refreshAccessToken();
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const requestPath = path.startsWith("/") ? path : `/${path}`;
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-Request-Id": crypto.randomUUID(),
    ...options.headers,
  };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (accessToken !== null) headers.Authorization = `Bearer ${accessToken}`;
  if (options.idempotencyKey !== undefined) headers["Idempotency-Key"] = options.idempotencyKey;
  if (options.ifMatch !== undefined) headers["If-Match"] = options.ifMatch;

  const response = await fetch(`${API_BASE}${requestPath}`, {
    method,
    cache: "no-store",
    credentials: "same-origin",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
  });
  const payload = await readPayload(response);
  const accepted = response.ok || options.acceptedStatuses?.includes(response.status) === true;
  if (accepted) return payload as T;

  const problem = normalizedProblem(response, payload, requestPath);
  const shouldRefresh =
    !requiresManualDatasourceOperationRetry(problem) &&
    options.allowRefresh !== false &&
    response.status === 401 &&
    problem.code === "AUTH_TOKEN_EXPIRED" &&
    canReplay(method, options.idempotencyKey);

  if (shouldRefresh) {
    await refreshAccessToken();
    return apiRequest<T>(path, { ...options, allowRefresh: false });
  }
  throw new ApiError(problem, retryAfterSeconds(response));
}

export async function apiDownload(
  path: string,
  options: Pick<RequestOptions, "signal" | "allowRefresh"> = {},
): Promise<ApiDownloadResponse> {
  const requestPath = path.startsWith("/") ? path : `/${path}`;
  const headers: Record<string, string> = {
    Accept: "text/plain",
    "X-Request-Id": crypto.randomUUID(),
  };
  if (accessToken !== null) headers.Authorization = `Bearer ${accessToken}`;

  const response = await fetch(`${API_BASE}${requestPath}`, {
    method: "GET",
    cache: "no-store",
    credentials: "same-origin",
    headers,
    signal: options.signal,
  });
  if (response.ok) {
    return {
      blob: await response.blob(),
      headers: response.headers,
    };
  }

  const payload = await readPayload(response);
  const problem = normalizedProblem(response, payload, requestPath);
  if (
    !requiresManualDatasourceOperationRetry(problem) &&
    options.allowRefresh !== false &&
    response.status === 401 &&
    problem.code === "AUTH_TOKEN_EXPIRED"
  ) {
    await refreshAccessToken();
    return apiDownload(path, { ...options, allowRefresh: false });
  }
  throw new ApiError(problem, retryAfterSeconds(response));
}

export function apiGet<T>(path: string, options: Omit<RequestOptions, "method"> = {}): Promise<T> {
  return apiRequest<T>(path, { ...options, method: "GET" });
}

export function apiPost<T>(
  path: string,
  body?: unknown,
  options: Omit<RequestOptions, "method" | "body"> = {},
): Promise<T> {
  return apiRequest<T>(path, { ...options, method: "POST", body });
}

export function apiPatch<T>(
  path: string,
  body: unknown,
  options: Omit<RequestOptions, "method" | "body"> = {},
): Promise<T> {
  return apiRequest<T>(path, { ...options, method: "PATCH", body });
}

export function apiPut<T>(
  path: string,
  body: unknown,
  options: Omit<RequestOptions, "method" | "body"> = {},
): Promise<T> {
  return apiRequest<T>(path, { ...options, method: "PUT", body });
}

export function apiDelete(
  path: string,
  options: Omit<RequestOptions, "method" | "body"> = {},
): Promise<null> {
  return apiRequest<null>(path, { ...options, method: "DELETE" });
}
