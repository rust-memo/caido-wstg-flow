<script setup lang="ts">
import type {
  CandidateDTO,
  CandidateStatus,
  CheckStatus,
  MessageDetails,
  ScanState,
  Snapshot,
  WstgSettings,
  WstgTestDTO,
} from "backend";
import {
  computed,
  nextTick,
  onMounted,
  onUnmounted,
  onUpdated,
  reactive,
  ref,
} from "vue";

import { useSDK } from "@/plugins/sdk";

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
const snapshot = ref<Snapshot>();
const activeTab = ref<Tab>("dashboard");
const scanState = ref<ScanState>({
  phase: "IDLE",
  queued: 0,
  active: 0,
  scanned: 0,
  dropped: 0,
  message: "Loading WSTG Flow",
});
const busy = ref(false);
const loading = ref(false);
const error = ref("");
const notice = ref("");
const candidateSearch = ref("");
const candidateStatusFilter = ref("ALL");
const candidateSeverityFilter = ref("ALL");
const checklistSearch = ref("");
const checklistStatusFilter = ref("ALL");
const assetSearch = ref("");
const selectedCandidateId = ref("");
const selectedTestId = ref("");
const message = ref<MessageDetails>();
const requestHost = ref<HTMLElement>();
const responseHost = ref<HTMLElement>();
const requestEditor = sdk.ui.httpRequestEditor();
const responseEditor = sdk.ui.httpResponseEditor();
const candidateStatus = ref<CandidateStatus>("NEW");
const candidateWstgId = ref("");
const candidateNotes = ref("");
const selectedPayload = ref("");
const baselineRequestId = ref("");
const variantRequestId = ref("");
const analyzeRequestId = ref("");
const testStatus = ref<CheckStatus>("NOT_TESTED");
const testNotes = ref("");
const settings = reactive<WstgSettings>({
  analysisEnabled: true,
  scopeOnly: true,
  autoHistory: true,
  maxHistoryEntries: 5_000,
  maxCandidates: 3_000,
  maxRequestBytes: 1024 * 1024,
  maxResponseBytes: 5 * 1024 * 1024,
  ignoredHosts: [],
});
const ignoredHostsText = ref("");

let snapshotListener: { stop: () => void } | undefined;
let stateListener: { stop: () => void } | undefined;

const tests = computed(() => snapshot.value?.tests ?? []);
const candidates = computed(() => snapshot.value?.candidates ?? []);
const findings = computed(() => snapshot.value?.findings ?? []);
const assets = computed(() => snapshot.value?.assets ?? []);
const selectedCandidate = computed(() =>
  candidates.value.find(
    (candidate) => candidate.id === selectedCandidateId.value,
  ),
);
const selectedTest = computed(() =>
  tests.value.find((test) => test.id === selectedTestId.value),
);
const testedCount = computed(
  () => tests.value.filter((test) => test.status !== "NOT_TESTED").length,
);
const passCount = computed(
  () => tests.value.filter((test) => test.status === "PASS").length,
);
const failCount = computed(
  () => tests.value.filter((test) => test.status === "FAIL").length,
);
const newCandidateCount = computed(
  () =>
    candidates.value.filter((candidate) => candidate.status === "NEW").length,
);
const verificationCount = computed(
  () =>
    candidates.value.filter(
      (candidate) =>
        candidate.baselineRequestId !== undefined &&
        candidate.variantRequestId !== undefined,
    ).length,
);
const coveragePercent = computed(() =>
  tests.value.length === 0
    ? 0
    : Math.round((testedCount.value / tests.value.length) * 100),
);
const filteredCandidates = computed(() =>
  candidates.value.filter((candidate) => {
    const query = candidateSearch.value.trim().toLowerCase();
    const haystack =
      `${candidate.title} ${candidate.ruleId} ${candidate.url} ${candidate.parameter} ${candidate.category} ${candidate.wstgId}`.toLowerCase();
    return (
      (candidateStatusFilter.value === "ALL" ||
        candidate.status === candidateStatusFilter.value) &&
      (candidateSeverityFilter.value === "ALL" ||
        candidate.severity === candidateSeverityFilter.value) &&
      (query === "" || haystack.includes(query))
    );
  }),
);
const filteredTests = computed(() =>
  tests.value.filter((test) => {
    const query = checklistSearch.value.trim().toLowerCase();
    const haystack =
      `${test.id} ${test.category} ${test.name} ${test.commonName} ${test.objectives}`.toLowerCase();
    return (
      (checklistStatusFilter.value === "ALL" ||
        test.status === checklistStatusFilter.value) &&
      (query === "" || haystack.includes(query))
    );
  }),
);
const filteredAssets = computed(() => {
  const query = assetSearch.value.trim().toLowerCase();
  return assets.value.filter((asset) =>
    `${asset.kind} ${asset.url} ${asset.sourceUrl}`
      .toLowerCase()
      .includes(query),
  );
});
const verifiedCandidates = computed(() =>
  candidates.value.filter(
    (candidate) =>
      candidate.baselineRequestId !== undefined ||
      candidate.variantRequestId !== undefined,
  ),
);
const maxRequestMb = computed({
  get: () => Math.round((settings.maxRequestBytes / 1024 / 1024) * 100) / 100,
  set: (value: number) => {
    settings.maxRequestBytes = Math.max(0.02, value) * 1024 * 1024;
  },
});
const maxResponseMb = computed({
  get: () => Math.round((settings.maxResponseBytes / 1024 / 1024) * 100) / 100,
  set: (value: number) => {
    settings.maxResponseBytes = Math.max(0.02, value) * 1024 * 1024;
  },
});

onMounted(async () => {
  mountEditors();
  snapshotListener = sdk.backend.onEvent("snapshot", (value) => {
    snapshot.value = value;
    scanState.value = value.state;
    normalizeSelections();
  });
  stateListener = sdk.backend.onEvent("scan-state", (value) => {
    scanState.value = value;
  });
  await refresh();
});

onUpdated(mountEditors);

onUnmounted(() => {
  snapshotListener?.stop();
  stateListener?.stop();
});

function mountEditors() {
  if (
    requestHost.value !== undefined &&
    !requestHost.value.contains(requestEditor.getElement())
  )
    requestHost.value.append(requestEditor.getElement());
  if (
    responseHost.value !== undefined &&
    !responseHost.value.contains(responseEditor.getElement())
  )
    responseHost.value.append(responseEditor.getElement());
}

async function refresh(hydrate = true) {
  if (loading.value) return;
  loading.value = true;
  try {
    const current = await sdk.backend.getSnapshot();
    snapshot.value = current;
    scanState.value = current.state;
    if (hydrate) hydrateSettings(current.settings);
    normalizeSelections();
    error.value = "";
  } catch (cause) {
    error.value = safeMessage(cause);
  } finally {
    loading.value = false;
  }
}

function normalizeSelections() {
  if (
    selectedCandidateId.value !== "" &&
    !candidates.value.some(
      (candidate) => candidate.id === selectedCandidateId.value,
    )
  )
    selectedCandidateId.value = "";
  if (
    selectedTestId.value !== "" &&
    !tests.value.some((test) => test.id === selectedTestId.value)
  )
    selectedTestId.value = "";
}

function hydrateSettings(value: WstgSettings) {
  Object.assign(settings, value);
  ignoredHostsText.value = value.ignoredHosts.join("\n");
}

async function selectCandidate(candidate: CandidateDTO) {
  selectedCandidateId.value = candidate.id;
  candidateStatus.value = candidate.status;
  candidateWstgId.value = candidate.wstgId;
  candidateNotes.value = candidate.decisionNotes;
  selectedPayload.value = candidate.payloads[0] ?? "";
  baselineRequestId.value = candidate.baselineRequestId ?? "";
  variantRequestId.value = candidate.variantRequestId ?? "";
  analyzeRequestId.value = candidate.requestId;
  await showMessage(candidate.requestId);
}

function selectTest(test: WstgTestDTO) {
  selectedTestId.value = test.id;
  testStatus.value = test.status;
  testNotes.value = test.notes;
}

async function showMessage(requestId: string | undefined) {
  if (requestId === undefined || requestId === "") return;
  await perform(async () => {
    message.value = await sdk.backend.getMessage(requestId);
    setEditor(
      requestEditor,
      message.value?.request ?? "Request is no longer available in Caido.",
    );
    setEditor(
      responseEditor,
      message.value?.response ?? "Response is no longer available in Caido.",
    );
  }, false);
}

function setEditor(
  editor: ReturnType<typeof sdk.ui.httpRequestEditor>,
  text: string,
) {
  const view = editor.getEditorView();
  view.dispatch({
    changes: { from: 0, to: view.state.doc.length, insert: text },
  });
}

async function saveCandidate() {
  const candidate = selectedCandidate.value;
  if (candidate === undefined) return;
  await perform(async () => {
    await sdk.backend.updateCandidate(
      candidate.id,
      candidateStatus.value,
      candidateWstgId.value,
      candidateNotes.value,
    );
    notice.value = "Candidate review saved.";
    await refresh(false);
  });
}

async function saveTest() {
  const test = selectedTest.value;
  if (test === undefined) return;
  await perform(async () => {
    await sdk.backend.updateTest(test.id, testStatus.value, testNotes.value);
    notice.value = `${test.id} updated.`;
    await refresh(false);
  });
}

async function analyzeManualRequest() {
  if (analyzeRequestId.value.trim() === "") {
    error.value = "Enter a Caido Request ID with a saved response.";
    return;
  }
  await perform(async () => {
    await sdk.backend.analyzeRequest(analyzeRequestId.value.trim());
    notice.value = "Selected request analyzed locally.";
    await refresh(false);
  });
}

async function prepareReplay() {
  const candidate = selectedCandidate.value;
  if (candidate === undefined || selectedPayload.value === "") return;
  if (
    !window.confirm(
      `Create a modified Replay session using payload '${selectedPayload.value}'? Nothing will be sent automatically.`,
    )
  )
    return;
  await perform(async () => {
    const id = await sdk.backend.prepareReplay(
      candidate.id,
      selectedPayload.value,
    );
    const sessionId = id as Parameters<typeof sdk.replay.renameSession>[0];
    await sdk.replay.renameSession(
      sessionId,
      `WSTG Flow - ${candidate.ruleId}`,
    );
    sdk.replay.openTab(sessionId);
    notice.value = "Modified Replay session created without sending.";
  });
}

async function attach(slot: "BASELINE" | "VARIANT") {
  const candidate = selectedCandidate.value;
  if (candidate === undefined) return;
  const requestId =
    slot === "BASELINE" ? baselineRequestId.value : variantRequestId.value;
  if (requestId.trim() === "") {
    error.value = `Enter a ${slot.toLowerCase()} Request ID.`;
    return;
  }
  if (
    !window.confirm(
      `Attach the saved in-scope exchange as ${slot === "BASELINE" ? "Baseline / Account A" : "Variant / Account B"}?`,
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.attachEvidence(candidate.id, requestId.trim(), slot);
    notice.value = `${slot} evidence attached.`;
    await refresh(false);
    const current = candidates.value.find((value) => value.id === candidate.id);
    if (current !== undefined) await selectCandidate(current);
  });
}

async function clearEvidence() {
  const candidate = selectedCandidate.value;
  if (
    candidate === undefined ||
    !window.confirm("Clear both A/B evidence links?")
  )
    return;
  await perform(async () => {
    await sdk.backend.clearEvidence(candidate.id);
    baselineRequestId.value = "";
    variantRequestId.value = "";
    await refresh(false);
  });
}

async function confirmFinding() {
  const candidate = selectedCandidate.value;
  if (candidate === undefined) return;
  if (
    !window.confirm(
      "Confirm this candidate as a real finding, mark its mapped WSTG test Fail, and publish a Caido Finding? Validate the evidence manually first.",
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.confirmAndPublish(candidate.id);
    notice.value = "Candidate confirmed and published as a Caido Finding.";
    await refresh(false);
  });
}

async function rescan() {
  await perform(async () => {
    await sdk.backend.rescanHistory();
    notice.value = "Passive History scan started.";
    await refresh(false);
  });
}

async function togglePause() {
  await perform(async () => {
    if (scanState.value.phase === "PAUSED") await sdk.backend.resume();
    else await sdk.backend.pause();
  }, false);
}

async function cancelScan() {
  await perform(async () => sdk.backend.cancel(), false);
}

async function clearCandidates() {
  if (
    !window.confirm(
      "Clear all unconfirmed candidates? Confirmed candidates and checklist progress remain.",
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.clearCandidates();
    selectedCandidateId.value = "";
    await refresh(false);
  });
}

async function applySettings() {
  await perform(async () => {
    settings.ignoredHosts = splitList(ignoredHostsText.value);
    const saved = await sdk.backend.saveSettings({ ...settings });
    hydrateSettings(saved);
    notice.value = "Settings saved; unconfirmed candidates are being rebuilt.";
    await refresh(false);
  });
}

async function perform(action: () => Promise<unknown>, lock = true) {
  if (lock && busy.value) return;
  if (lock) busy.value = true;
  error.value = "";
  try {
    await action();
  } catch (cause) {
    error.value = safeMessage(cause);
  } finally {
    if (lock) busy.value = false;
  }
}

function exportReport(format: "html" | "json" | "csv") {
  const current = snapshot.value;
  if (current === undefined) return;
  let content: string;
  let type: string;
  if (format === "html") {
    content = htmlReport(current);
    type = "text/html";
  } else if (format === "json") {
    content = JSON.stringify(exportableSnapshot(current), undefined, 2);
    type = "application/json";
  } else {
    content = findingCSV(current);
    type = "text/csv";
  }
  const blob = new Blob([content], { type });
  // eslint-disable-next-line compat/compat -- Caido desktop webview supports object URLs.
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `caido-wstg-flow-report.${format}`;
  anchor.click();
  // eslint-disable-next-line compat/compat -- Caido desktop webview supports object URLs.
  URL.revokeObjectURL(url);
}

function exportableSnapshot(current: Snapshot) {
  return {
    generatedAt: new Date().toISOString(),
    checklist: current.tests.map((test) => ({
      id: test.id,
      category: test.category,
      name: test.name,
      status: test.status,
      notes: redact(test.notes),
      candidateCount: test.candidateCount,
    })),
    findings: current.findings.map((finding) => ({
      title: redact(finding.title),
      severity: finding.severity,
      confidence: finding.confidence,
      url: redact(finding.url),
      method: finding.method,
      statusCode: finding.statusCode,
      wstgId: finding.wstgId,
      comment: redact(finding.comment),
      evidence: redact(finding.evidence),
      published: finding.published,
    })),
    candidates: current.candidates.map((candidate) => ({
      title: redact(candidate.title),
      ruleId: candidate.ruleId,
      category: candidate.category,
      severity: candidate.severity,
      confidence: candidate.confidence,
      url: redact(candidate.url),
      method: candidate.method,
      statusCode: candidate.statusCode,
      wstgId: candidate.wstgId,
      parameter: candidate.parameter,
      location: candidate.location,
      evidence: redact(candidate.evidence),
      explanation: redact(candidate.explanation),
      status: candidate.status,
      decisionNotes: redact(candidate.decisionNotes),
      occurrenceCount: candidate.occurrenceCount,
    })),
    assets: current.assets.map((asset) => ({
      kind: asset.kind,
      url: redact(asset.url),
      sourceUrl: redact(asset.sourceUrl),
      discoveredAt: asset.discoveredAt,
    })),
  };
}

function htmlReport(current: Snapshot): string {
  const checklist = current.tests
    .map(
      (test) =>
        `<tr><td>${escapeHTML(test.id)}</td><td>${escapeHTML(test.category)}</td><td>${escapeHTML(test.name)}</td><td>${escapeHTML(test.status)}</td><td>${escapeHTML(redact(test.notes))}</td></tr>`,
    )
    .join("");
  const findingRows = current.findings
    .map(
      (finding) =>
        `<tr><td>${escapeHTML(finding.severity)}</td><td>${escapeHTML(redact(finding.title))}</td><td>${escapeHTML(finding.wstgId)}</td><td>${escapeHTML(`${finding.method} ${redact(finding.url)}`)}</td><td>${escapeHTML(redact(`${finding.comment}\n${finding.evidence}`))}</td></tr>`,
    )
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8"><title>Caido WSTG Flow Report</title><style>body{font:14px system-ui;margin:32px;color:#17202a}h1{color:#e05a22}table{border-collapse:collapse;width:100%;margin:16px 0 32px}th,td{border:1px solid #ccd1d1;padding:7px;text-align:left;vertical-align:top;white-space:pre-wrap}th{background:#273746;color:white}</style></head><body><h1>Caido WSTG Flow Report</h1><p>Generated ${escapeHTML(new Date().toISOString())}. HTTP credentials and sensitive parameters are redacted.</p><h2>Checklist</h2><table><tr><th>ID</th><th>Category</th><th>Test</th><th>Status</th><th>Notes</th></tr>${checklist}</table><h2>Confirmed findings</h2><table><tr><th>Severity</th><th>Finding</th><th>WSTG</th><th>Endpoint</th><th>Evidence</th></tr>${findingRows}</table></body></html>`;
}

function findingCSV(current: Snapshot): string {
  const header = [
    "Severity",
    "Title",
    "URL",
    "Method",
    "Status",
    "WSTG",
    "Confidence",
    "Comment",
    "Evidence",
  ];
  const rows = current.findings.map((finding) => [
    finding.severity,
    redact(finding.title),
    redact(finding.url),
    finding.method,
    finding.statusCode,
    finding.wstgId,
    finding.confidence,
    redact(finding.comment),
    redact(finding.evidence),
  ]);
  return `${header.join(",")}\n${rows.map((row) => row.map(csv).join(",")).join("\n")}`;
}

function redact(value: string): string {
  return value
    .replace(
      /^(Authorization|Cookie|Set-Cookie|Proxy-Authorization):.*$/gim,
      "$1: [REDACTED]",
    )
    .replace(
      /(password|passwd|pwd|token|secret|api[_-]?key|client[_-]?secret)(=|%3d|:\s*|"\s*:\s*")[^&\s,}"]{3,}/gi,
      "$1$2[REDACTED]",
    );
}

function csv(value: unknown): string {
  let text =
    value === undefined || value === null
      ? ""
      : typeof value === "string" ||
          typeof value === "number" ||
          typeof value === "boolean" ||
          typeof value === "bigint"
        ? String(value)
        : JSON.stringify(value);
  if (/^[=+@-]/.test(text.trimStart())) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function escapeHTML(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function splitList(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[,\r\n]+/)
        .map((entry) => entry.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];
}

function statusLabel(value: string): string {
  return value.replaceAll("_", " ").toLowerCase();
}

function formatDate(value: string): string {
  return new Date(value).toLocaleString();
}

function safeMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

function activate(tab: Tab) {
  activeTab.value = tab;
  void nextTick(mountEditors);
}
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
      <div class="wstg-metrics">
        <span :class="`phase-${scanState.phase}`">{{ scanState.phase }}</span>
        <span>Coverage {{ testedCount }}/{{ tests.length }}</span>
        <span>Pass {{ passCount }}</span>
        <span>Fail {{ failCount }}</span>
        <span>New {{ newCandidateCount }}</span>
        <span>Findings {{ findings.length }}</span>
        <span>Queue {{ scanState.queued }}/{{ scanState.active }}</span>
        <span v-if="scanState.dropped">Dropped {{ scanState.dropped }}</span>
      </div>
    </header>
    <div class="wstg-state">{{ scanState.message }}</div>
    <div v-if="error" class="wstg-alert error">
      {{ error }} <button class="wstg-link" @click="error = ''">dismiss</button>
    </div>
    <div v-if="notice" class="wstg-alert notice">
      {{ notice }}
      <button class="wstg-link" @click="notice = ''">dismiss</button>
    </div>

    <nav class="wstg-tabs">
      <button
        class="wstg-tab"
        :class="{ active: activeTab === 'dashboard' }"
        @click="activate('dashboard')"
      >
        Dashboard
      </button>
      <button
        class="wstg-tab"
        :class="{ active: activeTab === 'checklist' }"
        @click="activate('checklist')"
      >
        Checklist ({{ tests.length }})
      </button>
      <button
        class="wstg-tab"
        :class="{ active: activeTab === 'candidates' }"
        @click="activate('candidates')"
      >
        Candidates ({{ candidates.length }})
      </button>
      <button
        class="wstg-tab"
        :class="{ active: activeTab === 'verification' }"
        @click="activate('verification')"
      >
        A/B Verification ({{ verificationCount }})
      </button>
      <button
        class="wstg-tab"
        :class="{ active: activeTab === 'assets' }"
        @click="activate('assets')"
      >
        Assets ({{ assets.length }})
      </button>
      <button
        class="wstg-tab"
        :class="{ active: activeTab === 'findings' }"
        @click="activate('findings')"
      >
        Findings ({{ findings.length }})
      </button>
      <button
        class="wstg-tab"
        :class="{ active: activeTab === 'reports' }"
        @click="activate('reports')"
      >
        Reports
      </button>
      <button
        class="wstg-tab"
        :class="{ active: activeTab === 'settings' }"
        @click="activate('settings')"
      >
        Settings
      </button>
    </nav>

    <section v-if="activeTab === 'dashboard'" class="wstg-content">
      <div class="wstg-dashboard-grid">
        <article class="wstg-stat hero">
          <span>WSTG coverage</span>
          <strong>{{ coveragePercent }}%</strong>
          <div class="wstg-progress">
            <i :style="{ width: `${coveragePercent}%` }" />
          </div>
          <small>{{ testedCount }} of {{ tests.length }} tests reviewed</small>
        </article>
        <article class="wstg-stat">
          <span>Candidate inbox</span><strong>{{ candidates.length }}</strong
          ><small>{{ newCandidateCount }} awaiting review</small>
        </article>
        <article class="wstg-stat">
          <span>Confirmed findings</span><strong>{{ findings.length }}</strong
          ><small>{{ failCount }} WSTG tests marked fail</small>
        </article>
        <article class="wstg-stat">
          <span>Discovered assets</span><strong>{{ assets.length }}</strong
          ><small>URLs and endpoints are never fetched</small>
        </article>
      </div>
      <div class="wstg-warning">
        Candidates are workflow hints, not findings. Passive analysis sends no
        requests. Suggested payloads create Replay sessions only and must be
        reviewed and sent manually.
      </div>
      <div class="wstg-toolbar">
        <button class="wstg-button primary" :disabled="busy" @click="rescan">
          Scan History
        </button>
        <button class="wstg-button" @click="togglePause">
          {{ scanState.phase === "PAUSED" ? "Resume" : "Pause" }}
        </button>
        <button class="wstg-button" @click="cancelScan">Cancel queued</button>
        <input
          v-model="analyzeRequestId"
          class="wstg-input grow"
          placeholder="Caido Request ID for explicit local analysis"
        />
        <button
          class="wstg-button"
          :disabled="busy"
          @click="analyzeManualRequest"
        >
          Analyze request
        </button>
      </div>
      <h2 class="wstg-section-title">Recent candidates</h2>
      <div class="wstg-table-wrap">
        <table class="wstg-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Severity</th>
              <th>Candidate</th>
              <th>Endpoint</th>
              <th>WSTG</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="candidate in candidates.slice(0, 12)"
              :key="candidate.id"
              @click="
                selectCandidate(candidate);
                activate('candidates');
              "
            >
              <td>{{ statusLabel(candidate.status) }}</td>
              <td>
                <span
                  class="wstg-badge"
                  :class="`severity-${candidate.severity}`"
                  >{{ candidate.severity }}</span
                >
              </td>
              <td>{{ candidate.title }}</td>
              <td>{{ candidate.method }} {{ candidate.url }}</td>
              <td>{{ candidate.wstgId || "—" }}</td>
              <td>{{ candidate.occurrenceCount }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section v-else-if="activeTab === 'checklist'" class="wstg-content">
      <div class="wstg-toolbar">
        <input
          v-model="checklistSearch"
          class="wstg-input grow"
          placeholder="Search WSTG ID, category, test, objective…"
        />
        <select v-model="checklistStatusFilter" class="wstg-select">
          <option value="ALL">All statuses</option>
          <option>NOT_TESTED</option>
          <option>IN_PROGRESS</option>
          <option>PASS</option>
          <option>FAIL</option>
          <option>NOT_APPLICABLE</option>
        </select>
      </div>
      <div class="wstg-table-wrap tall">
        <table class="wstg-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Category</th>
              <th>OWASP test</th>
              <th>Candidates</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="test in filteredTests"
              :key="test.id"
              :class="{ selected: selectedTestId === test.id }"
              @click="selectTest(test)"
            >
              <td>
                <code>{{ test.id }}</code>
              </td>
              <td>{{ test.category }}</td>
              <td>{{ test.name }}</td>
              <td>{{ test.candidateCount }}</td>
              <td>{{ statusLabel(test.status) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <article v-if="selectedTest" class="wstg-detail">
        <div class="wstg-detail-head">
          <div>
            <h2>{{ selectedTest.id }} · {{ selectedTest.name }}</h2>
            <p>{{ selectedTest.category }}</p>
          </div>
          <a
            class="wstg-button"
            :href="selectedTest.reference"
            target="_blank"
            rel="noreferrer"
            >OWASP reference</a
          >
        </div>
        <p class="wstg-objectives">
          {{
            selectedTest.objectives ||
            "No objective text in the bundled snapshot."
          }}
        </p>
        <div class="wstg-form-row">
          <label
            ><span>Status</span
            ><select v-model="testStatus" class="wstg-select">
              <option>NOT_TESTED</option>
              <option>IN_PROGRESS</option>
              <option>PASS</option>
              <option>FAIL</option>
              <option>NOT_APPLICABLE</option>
            </select></label
          ><label class="grow"
            ><span>Tester notes</span
            ><textarea v-model="testNotes" class="wstg-textarea short" /></label
          ><button
            class="wstg-button primary"
            :disabled="busy"
            @click="saveTest"
          >
            Save test
          </button>
        </div>
      </article>
    </section>

    <section v-else-if="activeTab === 'candidates'" class="wstg-content">
      <div class="wstg-toolbar">
        <input
          v-model="candidateSearch"
          class="wstg-input grow"
          placeholder="Search candidate, rule, endpoint, parameter…"
        />
        <select v-model="candidateStatusFilter" class="wstg-select">
          <option value="ALL">All statuses</option>
          <option>NEW</option>
          <option>REVIEWING</option>
          <option>CONFIRMED</option>
          <option>REJECTED</option>
        </select>
        <select v-model="candidateSeverityFilter" class="wstg-select">
          <option value="ALL">All severities</option>
          <option>Critical</option>
          <option>High</option>
          <option>Medium</option>
          <option>Low</option>
          <option>Information</option>
        </select>
        <button
          class="wstg-button danger"
          :disabled="busy"
          @click="clearCandidates"
        >
          Clear unconfirmed
        </button>
      </div>
      <div class="wstg-table-wrap tall">
        <table class="wstg-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Severity</th>
              <th>Candidate</th>
              <th>Parameter</th>
              <th>URL</th>
              <th>WSTG</th>
              <th>Verification</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="candidate in filteredCandidates"
              :key="candidate.id"
              :class="{ selected: selectedCandidateId === candidate.id }"
              @click="selectCandidate(candidate)"
            >
              <td>{{ statusLabel(candidate.status) }}</td>
              <td>
                <span
                  class="wstg-badge"
                  :class="`severity-${candidate.severity}`"
                  >{{ candidate.severity }}</span
                >
              </td>
              <td>{{ candidate.title }}</td>
              <td>
                {{ candidate.parameter || "—" }}
                <small>{{ candidate.location }}</small>
              </td>
              <td>{{ candidate.url }}</td>
              <td>{{ candidate.wstgId || "—" }}</td>
              <td>
                {{
                  candidate.comparison
                    ? statusLabel(candidate.comparison.outcome)
                    : candidate.baselineRequestId || candidate.variantRequestId
                      ? "partial"
                      : "—"
                }}
              </td>
              <td>{{ candidate.occurrenceCount }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <article v-if="selectedCandidate" class="wstg-detail">
        <div class="wstg-detail-head">
          <div>
            <h2>{{ selectedCandidate.title }}</h2>
            <p>
              {{ selectedCandidate.ruleId }} ·
              {{ selectedCandidate.category }} ·
              {{ selectedCandidate.confidence }}
            </p>
          </div>
          <button
            class="wstg-button accent"
            :disabled="busy || selectedCandidate.published"
            @click="confirmFinding"
          >
            {{
              selectedCandidate.published
                ? "Finding published"
                : "Confirm & publish Finding"
            }}
          </button>
        </div>
        <div class="wstg-candidate-grid">
          <div>
            <h3>Evidence</h3>
            <p>{{ selectedCandidate.evidence }}</p>
            <h3>Why it was flagged</h3>
            <p>{{ selectedCandidate.explanation }}</p>
          </div>
          <div>
            <h3>Recommended verification</h3>
            <p>{{ selectedCandidate.recommendedTest }}</p>
            <label
              ><span>Payload suggestion</span
              ><select v-model="selectedPayload" class="wstg-select wide">
                <option value="">No payload selected</option>
                <option
                  v-for="payload in selectedCandidate.payloads"
                  :key="payload"
                  :value="payload"
                >
                  {{ payload }}
                </option>
              </select></label
            ><button
              class="wstg-button"
              :disabled="!selectedPayload || busy"
              @click="prepareReplay"
            >
              Create Replay (do not send)
            </button>
          </div>
        </div>
        <div class="wstg-form-row">
          <label
            ><span>Review status</span
            ><select v-model="candidateStatus" class="wstg-select">
              <option>NEW</option>
              <option>REVIEWING</option>
              <option disabled>CONFIRMED</option>
              <option>REJECTED</option>
            </select></label
          ><label
            ><span>WSTG mapping</span
            ><select v-model="candidateWstgId" class="wstg-select wide">
              <option value="">Unmapped</option>
              <option v-for="test in tests" :key="test.id" :value="test.id">
                {{ test.id }} · {{ test.name }}
              </option>
            </select></label
          ><label class="grow"
            ><span>Decision notes</span
            ><textarea
              v-model="candidateNotes"
              class="wstg-textarea short"
            /></label
          ><button
            class="wstg-button primary"
            :disabled="busy || selectedCandidate.status === 'CONFIRMED'"
            @click="saveCandidate"
          >
            Save review
          </button>
        </div>
        <div class="wstg-editor-tabs">
          <button
            class="wstg-button"
            @click="showMessage(selectedCandidate.requestId)"
          >
            Source</button
          ><button
            class="wstg-button"
            :disabled="!selectedCandidate.baselineRequestId"
            @click="showMessage(selectedCandidate.baselineRequestId)"
          >
            Account A</button
          ><button
            class="wstg-button"
            :disabled="!selectedCandidate.variantRequestId"
            @click="showMessage(selectedCandidate.variantRequestId)"
          >
            Account B
          </button>
        </div>
        <div class="wstg-split">
          <div class="wstg-editor">
            <div>Request</div>
            <section ref="requestHost" />
          </div>
          <div class="wstg-editor">
            <div>Response</div>
            <section ref="responseHost" />
          </div>
        </div>
      </article>
    </section>

    <section v-else-if="activeTab === 'verification'" class="wstg-content">
      <div class="wstg-warning strong">
        Run both account requests manually in Replay first. WSTG Flow only links
        saved in-scope exchanges and compares them; it never sends A/B requests.
      </div>
      <div class="wstg-form-row">
        <label class="grow"
          ><span>Candidate</span
          ><select
            v-model="selectedCandidateId"
            class="wstg-select wide"
            @change="selectedCandidate && selectCandidate(selectedCandidate)"
          >
            <option value="">Choose candidate…</option>
            <option
              v-for="candidate in candidates"
              :key="candidate.id"
              :value="candidate.id"
            >
              {{ candidate.title }} · {{ candidate.method }} {{ candidate.url }}
            </option>
          </select></label
        >
      </div>
      <article v-if="selectedCandidate" class="wstg-detail">
        <div class="wstg-verification-grid">
          <label
            ><span>Baseline / Account A Request ID</span
            ><input v-model="baselineRequestId" class="wstg-input" /><button
              class="wstg-button primary"
              :disabled="busy"
              @click="attach('BASELINE')"
            >
              Attach Account A
            </button></label
          ><label
            ><span>Variant / Account B Request ID</span
            ><input v-model="variantRequestId" class="wstg-input" /><button
              class="wstg-button primary"
              :disabled="busy"
              @click="attach('VARIANT')"
            >
              Attach Account B
            </button></label
          >
        </div>
        <article
          v-if="selectedCandidate.comparison"
          class="wstg-comparison"
          :class="selectedCandidate.comparison.outcome.toLowerCase()"
        >
          <h2>{{ statusLabel(selectedCandidate.comparison.outcome) }}</h2>
          <pre>{{ selectedCandidate.comparison.summary }}</pre>
        </article>
        <div v-else class="wstg-empty">
          Attach both exchanges to calculate status, body similarity, identity
          fingerprint difference, header changes, and structured JSON
          differences.
        </div>
        <div class="wstg-toolbar">
          <button
            class="wstg-button"
            :disabled="!selectedCandidate.baselineRequestId"
            @click="showMessage(selectedCandidate.baselineRequestId)"
          >
            View Account A</button
          ><button
            class="wstg-button"
            :disabled="!selectedCandidate.variantRequestId"
            @click="showMessage(selectedCandidate.variantRequestId)"
          >
            View Account B</button
          ><button class="wstg-button danger" @click="clearEvidence">
            Clear evidence
          </button>
        </div>
        <div class="wstg-split">
          <div class="wstg-editor">
            <div>Request</div>
            <section ref="requestHost" />
          </div>
          <div class="wstg-editor">
            <div>Response</div>
            <section ref="responseHost" />
          </div>
        </div>
      </article>
      <div v-else-if="verifiedCandidates.length === 0" class="wstg-empty">
        No verification evidence attached yet.
      </div>
    </section>

    <section v-else-if="activeTab === 'assets'" class="wstg-content">
      <div class="wstg-warning">
        Assets are extracted passively from JavaScript responses. WSTG Flow
        never fetches discovered URLs or source maps.
      </div>
      <div class="wstg-toolbar">
        <input
          v-model="assetSearch"
          class="wstg-input grow"
          placeholder="Search kind, URL, source…"
        />
      </div>
      <div class="wstg-table-wrap tall">
        <table class="wstg-table">
          <thead>
            <tr>
              <th>Kind</th>
              <th>Discovered URL</th>
              <th>Source JavaScript</th>
              <th>Discovered</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="asset in filteredAssets" :key="asset.id">
              <td>{{ asset.kind }}</td>
              <td>{{ asset.url }}</td>
              <td>{{ asset.sourceUrl }}</td>
              <td>{{ formatDate(asset.discoveredAt) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section v-else-if="activeTab === 'findings'" class="wstg-content">
      <div class="wstg-warning">
        Only manually confirmed candidates appear here and in Caido Findings.
        Associated Caido requests can contain sensitive data even though the
        generated description is redacted.
      </div>
      <div v-if="findings.length" class="wstg-table-wrap">
        <table class="wstg-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Finding</th>
              <th>Endpoint</th>
              <th>WSTG</th>
              <th>Created</th>
              <th>Published</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="finding in findings"
              :key="finding.id"
              @click="showMessage(finding.requestId)"
            >
              <td>
                <span
                  class="wstg-badge"
                  :class="`severity-${finding.severity}`"
                  >{{ finding.severity }}</span
                >
              </td>
              <td>{{ finding.title }}</td>
              <td>{{ finding.method }} {{ finding.url }}</td>
              <td>{{ finding.wstgId || "—" }}</td>
              <td>{{ formatDate(finding.createdAt) }}</td>
              <td>{{ finding.published ? "yes" : "no" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="wstg-empty">No confirmed findings.</div>
    </section>

    <section v-else-if="activeTab === 'reports'" class="wstg-content">
      <div class="wstg-report-card">
        <h2>Redacted project report</h2>
        <p>
          Exports include checklist progress, confirmed findings, candidate
          decisions, A/B summaries, and discovered asset metadata.
          Authentication headers and sensitive parameter values are redacted.
          Raw HTTP is intentionally excluded.
        </p>
        <div class="wstg-toolbar">
          <button class="wstg-button primary" @click="exportReport('html')">
            Export HTML</button
          ><button class="wstg-button" @click="exportReport('json')">
            Export JSON</button
          ><button class="wstg-button" @click="exportReport('csv')">
            Export findings CSV
          </button>
        </div>
      </div>
    </section>

    <section v-else class="wstg-content">
      <div class="wstg-warning">
        Scope-only mode is recommended. Saving settings clears and rebuilds
        unconfirmed candidates from bounded History; confirmed findings and
        checklist progress remain.
      </div>
      <div class="wstg-settings-grid">
        <label class="wstg-setting-row"
          ><span>Enable passive analysis</span
          ><input v-model="settings.analysisEnabled" type="checkbox" /></label
        ><label class="wstg-setting-row"
          ><span>Analyze only Caido Scope</span
          ><input v-model="settings.scopeOnly" type="checkbox" /></label
        ><label class="wstg-setting-row"
          ><span>Scan existing History automatically</span
          ><input v-model="settings.autoHistory" type="checkbox" /></label
        ><label class="wstg-setting-row"
          ><span>Maximum History entries</span
          ><input
            v-model.number="settings.maxHistoryEntries"
            class="wstg-input"
            type="number"
            min="100"
            max="50000" /></label
        ><label class="wstg-setting-row"
          ><span>Maximum candidates</span
          ><input
            v-model.number="settings.maxCandidates"
            class="wstg-input"
            type="number"
            min="100"
            max="20000" /></label
        ><label class="wstg-setting-row"
          ><span>Maximum request body (MiB)</span
          ><input
            v-model.number="maxRequestMb"
            class="wstg-input"
            type="number"
            min="0.02"
            max="10"
            step="0.1" /></label
        ><label class="wstg-setting-row"
          ><span>Maximum response body (MiB)</span
          ><input
            v-model.number="maxResponseMb"
            class="wstg-input"
            type="number"
            min="0.02"
            max="20"
            step="0.1" /></label
        ><label class="wstg-setting-block"
          ><span>Ignored hosts</span
          ><textarea
            v-model="ignoredHostsText"
            class="wstg-textarea"
            placeholder="cdn.example.test"
          />
        </label>
      </div>
      <button
        class="wstg-button primary"
        :disabled="busy"
        @click="applySettings"
      >
        Save and rebuild
      </button>
    </section>
  </main>
</template>
