<script setup lang="ts">
import { computed } from "vue";

const {
  offset,
  limit,
  total,
  disabled = false,
} = defineProps<{
  offset: number;
  limit: number;
  total: number;
  disabled?: boolean;
}>();
const emit = defineEmits<{
  change: [offset: number];
}>();

const start = computed(() => (total === 0 ? 0 : offset + 1));
const end = computed(() => Math.min(offset + limit, total));
</script>

<template>
  <nav class="wstg-pagination" aria-label="Pagination">
    <span>{{ start }}–{{ end }} of {{ total }}</span>
    <button
      class="wstg-button"
      :disabled="disabled || offset === 0"
      aria-label="Previous page"
      @click="emit('change', Math.max(0, offset - limit))"
    >
      Previous
    </button>
    <button
      class="wstg-button"
      :disabled="disabled || offset + limit >= total"
      aria-label="Next page"
      @click="emit('change', offset + limit)"
    >
      Next
    </button>
  </nav>
</template>
