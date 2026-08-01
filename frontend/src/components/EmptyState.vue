<script setup lang="ts">
defineProps<{
  title: string;
  description: string;
  actionLabel?: string;
}>();

const emit = defineEmits<{
  action: [];
}>();
</script>

<template>
  <section class="empty-state">
    <div class="empty-state__mark" aria-hidden="true">○</div>
    <h3>{{ title }}</h3>
    <p>{{ description }}</p>
    <el-button v-if="actionLabel" type="primary" @click="emit('action')">{{ actionLabel }}</el-button>
  </section>
</template>
