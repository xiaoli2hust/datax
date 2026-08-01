import { computed, readonly, ref } from "vue";

import { fetchReadiness } from "../api/health";
import type { HealthResponse } from "../types";

const health = ref<HealthResponse | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);
let activeController: AbortController | null = null;

export function useHealth() {
  const ready = computed(() => health.value?.status === "UP");
  const workerReady = computed(() => health.value?.components.worker?.status === "UP");

  async function refresh(): Promise<void> {
    activeController?.abort();
    const controller = new AbortController();
    activeController = controller;
    loading.value = true;
    try {
      health.value = await fetchReadiness(controller.signal);
      error.value = null;
    } catch (caught) {
      if (controller.signal.aborted) return;
      error.value = caught instanceof Error ? caught.message : "无法连接本机状态接口";
    } finally {
      if (!controller.signal.aborted) loading.value = false;
    }
  }

  function stop(): void {
    activeController?.abort();
    activeController = null;
  }

  return {
    health: readonly(health),
    loading: readonly(loading),
    error: readonly(error),
    ready,
    workerReady,
    refresh,
    stop,
  };
}
