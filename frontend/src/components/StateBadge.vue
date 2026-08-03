<script setup lang="ts">
import { computed } from "vue";

import {
  dataEffectLabel,
  exclusivityStatusLabel,
  jobStatusLabel,
  processStateLabel,
  tagType,
  verificationStateLabel,
} from "../lib/display";
import type {
  DataEffect,
  JobStatus,
  ProcessState,
  TargetExclusivityStatus,
  VerificationState,
} from "../types";

const props = defineProps<{
  value: string;
  kind?: "job" | "process" | "effect" | "verification" | "exclusivity" | "generic";
}>();

const label = computed(() => {
  if (props.kind === "job") return jobStatusLabel[props.value as JobStatus] ?? props.value;
  if (props.kind === "process") return processStateLabel[props.value as ProcessState] ?? props.value;
  if (props.kind === "effect") return dataEffectLabel[props.value as DataEffect] ?? props.value;
  if (props.kind === "verification") {
    return verificationStateLabel[props.value as VerificationState] ?? props.value;
  }
  if (props.kind === "exclusivity") {
    return exclusivityStatusLabel[props.value as TargetExclusivityStatus] ?? props.value;
  }
  return props.value;
});
</script>

<template>
  <el-tag :type="tagType(value)" effect="plain" round>{{ label }}</el-tag>
</template>
