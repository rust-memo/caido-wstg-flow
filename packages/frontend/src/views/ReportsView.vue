<script setup lang="ts">
import type { ReportFormat } from "backend";
import { ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { safeMessage } from "@/utils";

const sdk = useSDK();
const busy = ref(false);

async function exportReport(format: ReportFormat) {
  if (busy.value) return;
  busy.value = true;
  try {
    const file = await sdk.backend.exportReport(format);
    const blob = new Blob([file.content], { type: file.mediaType });
    // eslint-disable-next-line compat/compat -- Caido desktop webview supports object URLs.
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = file.filename;
    anchor.click();
    // eslint-disable-next-line compat/compat -- Caido desktop webview supports object URLs.
    URL.revokeObjectURL(url);
    sdk.window.showToast(`${file.filename} exported.`, { variant: "success" });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="wstg-content">
    <article class="wstg-report-card">
      <h2>Redacted project report</h2>
      <p>
        HTML and JSON include checklist progress, confirmed findings, candidate
        decisions, A/B summaries, and discovered asset metadata. CSV contains
        confirmed findings. Raw HTTP and request identifiers are excluded.
      </p>
      <div class="wstg-toolbar">
        <button
          class="wstg-button primary"
          :disabled="busy"
          @click="exportReport('html')"
        >
          Export HTML
        </button>
        <button
          class="wstg-button"
          :disabled="busy"
          @click="exportReport('json')"
        >
          Export JSON
        </button>
        <button
          class="wstg-button"
          :disabled="busy"
          @click="exportReport('csv')"
        >
          Export findings CSV
        </button>
      </div>
    </article>
  </section>
</template>
