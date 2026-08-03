import { ApiError, isApiError } from "../api/client";
import type {
  DataEffect,
  JobStatus,
  ProcessState,
  TargetExclusivityStatus,
  VerificationState,
} from "../types";

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

export function shortId(value: string | null | undefined): string {
  if (!value) return "—";
  return value.length > 13 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

export function errorMessage(error: unknown): string {
  if (isApiError(error)) {
    return error.problem.detail ? `${error.problem.title}：${error.problem.detail}` : error.problem.title;
  }
  return error instanceof Error ? error.message : "发生未知错误";
}

export function asApiError(error: unknown): ApiError | null {
  return isApiError(error) ? error : null;
}

export const jobStatusLabel: Record<JobStatus, string> = {
  DRAFT: "草稿",
  VALID: "已校验",
  PUBLISHED: "已发布",
  ARCHIVED: "已归档",
};

export const processStateLabel: Record<ProcessState, string> = {
  QUEUED: "排队中",
  STARTING: "启动中",
  RUNNING: "运行中",
  VERIFYING: "核验中",
  SUCCEEDED: "复制已核验成功",
  FAILED: "失败",
  TIMED_OUT: "已超时",
  CANCEL_REQUESTED: "取消中",
  CANCELED: "已取消",
  LOST: "状态丢失",
};

export const dataEffectLabel: Record<DataEffect, string> = {
  NONE: "未发现目标写入",
  POSSIBLE: "可能已写入",
  CONFIRMED: "影响已确认",
  UNKNOWN: "影响未知",
};

export const verificationStateLabel: Record<VerificationState, string> = {
  NOT_STARTED: "尚未核验",
  VERIFYING: "核验中",
  PASSED: "核验通过",
  FAILED: "核验不一致",
  INCONCLUSIVE: "核验无结论",
};

export const exclusivityStatusLabel: Record<TargetExclusivityStatus, string> = {
  ACTIVE: "声明有效",
  REVOKED: "声明已撤回",
  EXPIRED: "声明已过期",
};

export function tagType(
  value: string,
): "success" | "warning" | "danger" | "info" | "primary" {
  if (["SUCCEEDED", "PASSED", "ACTIVE", "VALID", "PUBLISHED", "UP"].includes(value)) return "success";
  if (
    [
      "QUEUED",
      "STARTING",
      "RUNNING",
      "VERIFYING",
      "CANCEL_REQUESTED",
      "POSSIBLE",
      "UNKNOWN",
      "INCONCLUSIVE",
      "DEGRADED",
    ].includes(value)
  ) {
    return "warning";
  }
  if (["FAILED", "TIMED_OUT", "LOST", "REVOKED", "EXPIRED", "DOWN"].includes(value)) return "danger";
  if (["DRAFT", "ARCHIVED", "CANCELED", "NONE", "NOT_STARTED"].includes(value)) return "info";
  return "primary";
}
