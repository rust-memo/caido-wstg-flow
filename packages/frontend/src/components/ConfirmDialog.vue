<script setup lang="ts">
import { nextTick, ref, watch } from "vue";

const { open, title, message, confirmLabel, danger } = defineProps<{
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  danger: boolean;
}>();
const emit = defineEmits<{
  confirm: [];
  cancel: [];
}>();
const confirmButton = ref<HTMLButtonElement>();

watch(
  () => open,
  async (open) => {
    if (open) {
      await nextTick();
      confirmButton.value?.focus();
    }
  },
);
</script>

<template>
  <div
    v-if="open"
    class="wstg-dialog-backdrop"
    role="presentation"
    @click.self="emit('cancel')"
  >
    <section
      class="wstg-dialog"
      role="alertdialog"
      aria-modal="true"
      :aria-labelledby="'wstg-confirm-title'"
      :aria-describedby="'wstg-confirm-message'"
      @keydown.esc="emit('cancel')"
    >
      <h2 id="wstg-confirm-title">{{ title }}</h2>
      <p id="wstg-confirm-message">{{ message }}</p>
      <div class="wstg-toolbar dialog-actions">
        <button class="wstg-button" @click="emit('cancel')">Cancel</button>
        <button
          ref="confirmButton"
          class="wstg-button"
          :class="danger ? 'danger' : 'primary'"
          @click="emit('confirm')"
        >
          {{ confirmLabel }}
        </button>
      </div>
    </section>
  </div>
</template>
