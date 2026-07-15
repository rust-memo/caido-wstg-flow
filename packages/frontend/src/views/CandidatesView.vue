<script setup lang="ts">
import type {
  CandidateDTO,
  CandidateQuery,
  CandidateStatus,
  Page,
  WstgTestDTO,
} from "backend";
import { onMounted, onUpdated, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import { safeMessage, statusLabel } from "@/utils";

const {
  tests,
  revision,
  focusId = "",
} = defineProps<{
  tests: WstgTestDTO[];
  revision: number;
  focusId?: string;
}>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const confirm = useConfirm();
const page = ref<Page<CandidateDTO>>({
  items: [],
  total: 0,
  offset: 0,
  limit: 50,
});
const search = ref("");
const statusFilter = ref<CandidateQuery["status"]>("ALL");
const severityFilter = ref<CandidateQuery["severity"]>("ALL");
const loading = ref(false);
const busy = ref(false);
const selected = ref<CandidateDTO>();
const candidateStatus = ref<CandidateStatus>("NEW");
const candidateWstgId = ref("");
const candidateNotes = ref("");
const selectedPayload = ref("");
const requestHost = ref<HTMLElement>();
const responseHost = ref<HTMLElement>();
const requestEditor = sdk.ui.httpRequestEditor();
const responseEditor = sdk.ui.httpResponseEditor();
let reloadTimer: number | undefined;

onMounted(async () => {
  mountEditors();
  await load(0);
  await focusCandidate(focusId);
});
onUpdated(mountEditors);

watch([search, statusFilter, severityFilter], () => scheduleLoad(0));
watch(
  () => revision,
  () => scheduleLoad(page.value.offset, true),
);
watch(
  () => focusId,
  (id) => focusCandidate(id),
);

function query(offset: number): CandidateQuery {
  return {
    search: search.value,
    status: statusFilter.value,
    severity: severityFilter.value,
    offset,
    limit: page.value.limit,
  };
}

function scheduleLoad(offset: number, refreshSelected = false) {
  if (reloadTimer !== undefined) window.clearTimeout(reloadTimer);
  reloadTimer = window.setTimeout(() => {
    reloadTimer = undefined;
    void load(offset, refreshSelected);
  }, 250);
}

async function load(offset: number, refreshSelected = false) {
  loading.value = true;
  try {
    page.value = await sdk.backend.listCandidates(query(offset));
    if (refreshSelected && selected.value !== undefined) {
      const current = await sdk.backend.getCandidate(selected.value.id);
      if (current !== undefined) hydrateSelected(current);
    }
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    loading.value = false;
  }
}

async function select(candidate: CandidateDTO) {
  hydrateSelected(candidate);
  await showMessage(candidate.requestId);
}

async function focusCandidate(id: string | undefined) {
  if (id === undefined || id === "" || selected.value?.id === id) return;
  try {
    const candidate = await sdk.backend.getCandidate(id);
    if (candidate !== undefined) await select(candidate);
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

function hydrateSelected(candidate: CandidateDTO) {
  selected.value = candidate;
  candidateStatus.value = candidate.status;
  candidateWstgId.value = candidate.wstgId;
  candidateNotes.value = candidate.decisionNotes;
  selectedPayload.value = candidate.payloads[0] ?? "";
}

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

async function showMessage(requestId: string) {
  try {
    const message = await sdk.backend.getMessage(requestId);
    const requestView = requestEditor.getEditorView();
    requestView.dispatch({
      changes: {
        from: 0,
        to: requestView.state.doc.length,
        insert: message?.request ?? "Request is no longer available in Caido.",
      },
    });
    const responseView = responseEditor.getEditorView();
    responseView.dispatch({
      changes: {
        from: 0,
        to: responseView.state.doc.length,
        insert:
          message?.response ?? "Response is no longer available in Caido.",
      },
    });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

async function run(action: () => Promise<unknown>, success?: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    if (success !== undefined)
      sdk.window.showToast(success, { variant: "success" });
    await load(page.value.offset, true);
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}

async function saveCandidate() {
  if (selected.value === undefined) return;
  await run(
    async () =>
      sdk.backend.updateCandidate(
        selected.value!.id,
        candidateStatus.value,
        candidateWstgId.value,
        candidateNotes.value,
      ),
    "Candidate review saved.",
  );
}

async function prepareReplay() {
  if (selected.value === undefined || selectedPayload.value === "") return;
  const accepted = await confirm({
    title: "Create unsent Replay",
    message: `Create a modified Replay session using payload '${selectedPayload.value}'? Nothing will be sent automatically.`,
    confirmLabel: "Create Replay",
  });
  if (!accepted) return;
  await run(async () => {
    const id = await sdk.backend.prepareReplay(
      selected.value!.id,
      selectedPayload.value,
    );
    const sessionId = id as Parameters<typeof sdk.replay.renameSession>[0];
    await sdk.replay.renameSession(
      sessionId,
      `WSTG Flow - ${selected.value!.ruleId}`,
    );
    sdk.replay.openTab(sessionId);
  }, "Modified Replay session created without sending.");
}

async function publishFinding() {
  if (selected.value === undefined) return;
  const accepted = await confirm({
    title: "Confirm and publish finding",
    message:
      "Confirm this candidate as a real finding, mark its mapped WSTG test Fail, and publish it to Caido Findings? Validate the evidence manually first.",
    confirmLabel: "Publish finding",
    danger: true,
  });
  if (!accepted) return;
  await run(
    async () => sdk.backend.confirmAndPublish(selected.value!.id),
    "Candidate confirmed and published.",
  );
}

async function clearCandidates() {
  const accepted = await confirm({
    title: "Clear unconfirmed candidates",
    message:
      "Clear all unconfirmed candidates? Confirmed candidates and checklist progress remain.",
    confirmLabel: "Clear candidates",
    danger: true,
  });
  if (!accepted) return;
  await run(async () => {
    await sdk.backend.clearCandidates();
    selected.value = undefined;
  }, "Unconfirmed candidates cleared.");
}
</script>

<template>
  <section class="wstg-content">
    <div class="wstg-toolbar">
      <input
        v-model="search"
        class="wstg-input grow"
        aria-label="Search candidates"
        placeholder="Search title, rule, endpoint, parameter, WSTG…"
      />
      <select v-model="statusFilter" class="wstg-select" aria-label="Status">
        <option value="ALL">All statuses</option>
        <option>NEW</option>
        <option>REVIEWING</option>
        <option>CONFIRMED</option>
        <option>REJECTED</option>
      </select>
      <select
        v-model="severityFilter"
        class="wstg-select"
        aria-label="Severity"
      >
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
    <div class="wstg-table-wrap tall" :aria-busy="loading">
      <table class="wstg-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Severity</th>
            <th>Candidate</th>
            <th>Parameter</th>
            <th>Endpoint</th>
            <th>WSTG</th>
            <th>Seen</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="candidate in page.items"
            :key="candidate.id"
            :class="{ selected: selected?.id === candidate.id }"
          >
            <td>{{ statusLabel(candidate.status) }}</td>
            <td>
              <span
                class="wstg-badge"
                :class="`severity-${candidate.severity}`"
              >
                {{ candidate.severity }}
              </span>
            </td>
            <td>
              <button class="wstg-row-button" @click="select(candidate)">
                {{ candidate.title }}
              </button>
              <small>{{ candidate.ruleId }}</small>
            </td>
            <td>{{ candidate.parameter || "—" }} {{ candidate.location }}</td>
            <td>{{ candidate.method }} {{ candidate.url }}</td>
            <td>{{ candidate.wstgId || "—" }}</td>
            <td>{{ candidate.occurrenceCount }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <PaginationControls
      :offset="page.offset"
      :limit="page.limit"
      :total="page.total"
      :disabled="loading"
      @change="load"
    />
    <article v-if="selected" class="wstg-detail">
      <div class="wstg-detail-head">
        <div>
          <h2>{{ selected.title }}</h2>
          <p>
            {{ selected.ruleId }} · {{ selected.category }} ·
            {{ selected.confidence }}
          </p>
        </div>
        <button
          class="wstg-button accent"
          :disabled="busy || selected.published"
          @click="publishFinding"
        >
          {{
            selected.published
              ? "Finding published"
              : "Confirm & publish Finding"
          }}
        </button>
      </div>
      <div class="wstg-candidate-grid">
        <div>
          <h3>Evidence</h3>
          <p>{{ selected.evidence }}</p>
          <h3>Why it was flagged</h3>
          <p>{{ selected.explanation }}</p>
        </div>
        <div>
          <h3>Recommended verification</h3>
          <p>{{ selected.recommendedTest }}</p>
          <label>
            <span>Payload suggestion</span>
            <select v-model="selectedPayload" class="wstg-select wide">
              <option value="">No payload selected</option>
              <option
                v-for="payload in selected.payloads"
                :key="payload"
                :value="payload"
              >
                {{ payload }}
              </option>
            </select>
          </label>
          <button
            class="wstg-button"
            :disabled="!selectedPayload || busy"
            @click="prepareReplay"
          >
            Create Replay (do not send)
          </button>
        </div>
      </div>
      <div class="wstg-form-row">
        <label>
          <span>Review status</span>
          <select v-model="candidateStatus" class="wstg-select">
            <option>NEW</option>
            <option>REVIEWING</option>
            <option disabled>CONFIRMED</option>
            <option>REJECTED</option>
          </select>
        </label>
        <label>
          <span>WSTG mapping</span>
          <select v-model="candidateWstgId" class="wstg-select wide">
            <option value="">Unmapped</option>
            <option v-for="test in tests" :key="test.id" :value="test.id">
              {{ test.id }} · {{ test.name }}
            </option>
          </select>
        </label>
        <label class="grow">
          <span>Decision notes</span>
          <textarea v-model="candidateNotes" class="wstg-textarea short" />
        </label>
        <button
          class="wstg-button primary"
          :disabled="busy || selected.status === 'CONFIRMED'"
          @click="saveCandidate"
        >
          Save review
        </button>
      </div>
      <div class="wstg-editor-tabs">
        <button class="wstg-button" @click="showMessage(selected.requestId)">
          Source
        </button>
        <button
          class="wstg-button"
          :disabled="!selected.baselineRequestId"
          @click="
            selected.baselineRequestId &&
            showMessage(selected.baselineRequestId)
          "
        >
          Account A
        </button>
        <button
          class="wstg-button"
          :disabled="!selected.variantRequestId"
          @click="
            selected.variantRequestId && showMessage(selected.variantRequestId)
          "
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
    <div v-else-if="!loading && page.total === 0" class="wstg-empty">
      No candidates match the current filters.
    </div>
  </section>
</template>
