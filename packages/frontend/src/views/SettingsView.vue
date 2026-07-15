<script setup lang="ts">
import type { WstgSettings } from "backend";
import { computed, reactive, ref, watch } from "vue";

import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import { safeMessage, splitList } from "@/utils";

const { settings } = defineProps<{ settings: WstgSettings }>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const confirm = useConfirm();
const form = reactive<WstgSettings>({ ...settings, ignoredHosts: [] });
const ignoredHosts = ref("");
const busy = ref(false);

watch(
  () => settings,
  (value) => hydrate(value),
  { immediate: true, deep: true },
);

const maxRequestMb = computed({
  get: () => Math.round((form.maxRequestBytes / 1024 / 1024) * 100) / 100,
  set: (value: number) => {
    form.maxRequestBytes = Math.max(0.02, value) * 1024 * 1024;
  },
});
const maxResponseMb = computed({
  get: () => Math.round((form.maxResponseBytes / 1024 / 1024) * 100) / 100,
  set: (value: number) => {
    form.maxResponseBytes = Math.max(0.02, value) * 1024 * 1024;
  },
});

function hydrate(value: WstgSettings) {
  Object.assign(form, value, { ignoredHosts: [...value.ignoredHosts] });
  ignoredHosts.value = value.ignoredHosts.join("\n");
}

async function save() {
  if (busy.value) return;
  busy.value = true;
  try {
    form.ignoredHosts = splitList(ignoredHosts.value);
    const saved = await sdk.backend.saveSettings({
      ...form,
      ignoredHosts: [...form.ignoredHosts],
    });
    hydrate(saved);
    sdk.window.showToast(
      "Settings saved. Existing candidates were not changed.",
      { variant: "success" },
    );
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}

async function rebuild() {
  const accepted = await confirm({
    title: "Rebuild unconfirmed candidates",
    message:
      "Delete every unconfirmed candidate and rebuild the queue from bounded Caido History using the saved settings? Confirmed findings and checklist progress remain.",
    confirmLabel: "Rebuild candidates",
    danger: true,
  });
  if (!accepted || busy.value) return;
  busy.value = true;
  try {
    await sdk.backend.rebuildCandidates();
    sdk.window.showToast("Candidate rebuild started.", { variant: "success" });
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="wstg-content">
    <div class="wstg-warning">
      Saving settings is non-destructive. Use the separate rebuild action only
      when you intentionally want to replace unconfirmed candidates.
    </div>
    <div class="wstg-settings-grid">
      <label class="wstg-setting-row">
        <span>Enable automatic passive analysis</span>
        <input v-model="form.analysisEnabled" type="checkbox" />
      </label>
      <label class="wstg-setting-row">
        <span>Analyze only Caido Scope</span>
        <input v-model="form.scopeOnly" type="checkbox" />
      </label>
      <label class="wstg-setting-row">
        <span>Scan existing History automatically</span>
        <input v-model="form.autoHistory" type="checkbox" />
      </label>
      <label class="wstg-setting-row">
        <span>Maximum History entries</span>
        <input
          v-model.number="form.maxHistoryEntries"
          class="wstg-input"
          type="number"
          min="100"
          max="50000"
        />
      </label>
      <label class="wstg-setting-row">
        <span>Maximum candidates</span>
        <input
          v-model.number="form.maxCandidates"
          class="wstg-input"
          type="number"
          min="100"
          max="20000"
        />
      </label>
      <label class="wstg-setting-row">
        <span>Maximum request (MiB)</span>
        <input
          v-model.number="maxRequestMb"
          class="wstg-input"
          type="number"
          min="0.02"
          max="10"
          step="0.1"
        />
      </label>
      <label class="wstg-setting-row">
        <span>Maximum response (MiB)</span>
        <input
          v-model.number="maxResponseMb"
          class="wstg-input"
          type="number"
          min="0.02"
          max="20"
          step="0.1"
        />
      </label>
      <label class="wstg-setting-block">
        <span>Ignored hosts</span>
        <textarea
          v-model="ignoredHosts"
          class="wstg-textarea"
          placeholder="cdn.example.test"
        />
      </label>
    </div>
    <div class="wstg-toolbar">
      <button class="wstg-button primary" :disabled="busy" @click="save">
        Save settings
      </button>
      <button class="wstg-button danger" :disabled="busy" @click="rebuild">
        Rebuild unconfirmed candidates
      </button>
    </div>
  </section>
</template>
