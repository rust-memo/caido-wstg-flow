<script setup lang="ts">
import type { Overview, ScanState } from "backend";
import { onMounted, onUnmounted, provide, reactive, ref } from "vue";

import ConfirmDialog from "@/components/ConfirmDialog.vue";
import { ConfirmKey, type ConfirmOptions } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import AssetsView from "@/views/AssetsView.vue";
import CandidatesView from "@/views/CandidatesView.vue";
import ChecklistView from "@/views/ChecklistView.vue";
import DashboardView from "@/views/DashboardView.vue";
import FindingsView from "@/views/FindingsView.vue";
import ReportsView from "@/views/ReportsView.vue";
import SettingsView from "@/views/SettingsView.vue";
import VerificationView from "@/views/VerificationView.vue";

type Tab =
  | "dashboard"
  | "checklist"
  | "candidates"
  | "verification"
  | "assets"
  | "findings"
  | "reports"
  | "settings";

const sdk = useSDK();
const overview = ref<Overview>();
const activeTab = ref<Tab>("dashboard");
const revision = ref(0);
const candidateFocusId = ref("");
const loading = ref(false);
const state = ref<ScanState>({
  phase: "IDLE",
  queued: 0,
  active: 0,
  scanned: 0,
  dropped: 0,
  message: "Loading WSTG Flow",
});
const dialog = reactive({
  open: false,
  title: "",
  message: "",
  confirmLabel: "Confirm",
  danger: false,
});
let dialogResolver: ((accepted: boolean) => void) | undefined;
let changeListener: { stop: () => void } | undefined;
let stateListener: { stop: () => void } | undefined;
let overviewRefreshPending = false;

provide(ConfirmKey, (options: ConfirmOptions) => {
  if (dialogResolver !== undefined) dialogResolver(false);
  Object.assign(dialog, {
    open: true,
    title: options.title,
    message: options.message,
    confirmLabel: options.confirmLabel ?? "Confirm",
    danger: options.danger === true,
  });
  // eslint-disable-next-line compat/compat -- Caido's desktop webview supports Promise.
  return new Promise<boolean>((resolve) => {
    dialogResolver = resolve;
  });
});

onMounted(async () => {
  changeListener = sdk.backend.onEvent("data-changed", () => {
    revision.value += 1;
    void refreshOverview();
  });
  stateListener = sdk.backend.onEvent("scan-state", (value) => {
    state.value = value;
    if (overview.value !== undefined) overview.value.state = value;
  });
  await refreshOverview();
});

onUnmounted(() => {
  changeListener?.stop();
  stateListener?.stop();
  dialogResolver?.(false);
});

async function refreshOverview() {
  if (loading.value) {
    overviewRefreshPending = true;
    return;
  }
  loading.value = true;
  try {
    overview.value = await sdk.backend.getOverview();
    state.value = overview.value.state;
  } catch (cause) {
    sdk.window.showToast(
      cause instanceof Error ? cause.message : String(cause),
      { variant: "error" },
    );
  } finally {
    loading.value = false;
    if (overviewRefreshPending) {
      overviewRefreshPending = false;
      void refreshOverview();
    }
  }
}

function resolveDialog(accepted: boolean) {
  dialog.open = false;
  const resolve = dialogResolver;
  dialogResolver = undefined;
  resolve?.(accepted);
}

function openCandidate(id: string) {
  candidateFocusId.value = id;
  activeTab.value = "candidates";
}

const tabs: Array<{ id: Tab; label: string }> = [
  { id: "dashboard", label: "Dashboard" },
  { id: "checklist", label: "Checklist" },
  { id: "candidates", label: "Candidates" },
  { id: "verification", label: "A/B Verification" },
  { id: "assets", label: "Assets" },
  { id: "findings", label: "Findings" },
  { id: "reports", label: "Reports" },
  { id: "settings", label: "Settings" },
];
</script>

<template>
  <main class="wstg-shell">
    <header class="wstg-header">
      <div>
        <div class="wstg-title">WSTG Flow for Caido</div>
        <div class="wstg-subtitle">
          OWASP WSTG checklist · Passive candidate discovery · Manual A/B
          evidence
        </div>
      </div>
      <div v-if="overview" class="wstg-metrics" aria-label="Project summary">
        <span :class="`phase-${state.phase}`">{{ state.phase }}</span>
        <span
          >Coverage {{ overview.summary.testedCount }}/{{
            overview.tests.length
          }}</span
        >
        <span>Pass {{ overview.summary.passCount }}</span>
        <span>Fail {{ overview.summary.failCount }}</span>
        <span>New {{ overview.summary.newCandidateCount }}</span>
        <span>Findings {{ overview.summary.findingTotal }}</span>
        <span>Queue {{ state.queued }}/{{ state.active }}</span>
        <span v-if="state.dropped">Dropped {{ state.dropped }}</span>
      </div>
    </header>
    <div class="wstg-state" role="status" aria-live="polite">
      {{ state.message }}
    </div>
    <nav class="wstg-tabs" role="tablist" aria-label="WSTG Flow sections">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        class="wstg-tab"
        :class="{ active: activeTab === tab.id }"
        role="tab"
        :aria-selected="activeTab === tab.id"
        @click="activeTab = tab.id"
      >
        {{ tab.label }}
        <template v-if="overview">
          <template v-if="tab.id === 'checklist'">
            ({{ overview.tests.length }})</template
          >
          <template v-else-if="tab.id === 'candidates'">
            ({{ overview.summary.candidateTotal }})</template
          >
          <template v-else-if="tab.id === 'assets'">
            ({{ overview.summary.assetTotal }})</template
          >
          <template v-else-if="tab.id === 'findings'">
            ({{ overview.summary.findingTotal }})</template
          >
        </template>
      </button>
    </nav>

    <div v-if="loading && !overview" class="wstg-empty" aria-busy="true">
      Loading project data…
    </div>
    <template v-else-if="overview">
      <DashboardView
        v-if="activeTab === 'dashboard'"
        :overview="overview"
        @refresh="refreshOverview"
        @open-candidate="openCandidate"
      />
      <ChecklistView
        v-else-if="activeTab === 'checklist'"
        :tests="overview.tests"
        @refresh="refreshOverview"
      />
      <CandidatesView
        v-else-if="activeTab === 'candidates'"
        :tests="overview.tests"
        :revision="revision"
        :focus-id="candidateFocusId"
        @refresh="refreshOverview"
      />
      <VerificationView
        v-else-if="activeTab === 'verification'"
        :revision="revision"
        @refresh="refreshOverview"
      />
      <AssetsView v-else-if="activeTab === 'assets'" :revision="revision" />
      <FindingsView v-else-if="activeTab === 'findings'" :revision="revision" />
      <ReportsView v-else-if="activeTab === 'reports'" />
      <SettingsView
        v-else
        :settings="overview.settings"
        @refresh="refreshOverview"
      />
    </template>

    <ConfirmDialog
      :open="dialog.open"
      :title="dialog.title"
      :message="dialog.message"
      :confirm-label="dialog.confirmLabel"
      :danger="dialog.danger"
      @confirm="resolveDialog(true)"
      @cancel="resolveDialog(false)"
    />
  </main>
</template>
