import type { HealthResponse } from "../types";

import { apiGet } from "./client";

export async function fetchReadiness(signal?: AbortSignal): Promise<HealthResponse> {
  return apiGet<HealthResponse>("/health/ready", {
    signal,
    allowRefresh: false,
    acceptedStatuses: [503],
  });
}
