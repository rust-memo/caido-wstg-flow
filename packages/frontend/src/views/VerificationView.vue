<script setup lang="ts">
import type { CandidateDTO, Page } from "backend";
import { onMounted, onUpdated, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import { safeMessage, statusLabel } from "@/utils";

const { revision } = defineProps<{ revision: number }>();
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
const selected = ref<CandidateDTO>();
const baselineRequestId = ref("");
const variantRequestId = ref("");
const loading = ref(false);
const busy = ref(false);
const requestHost = ref<HTMLElement>();
const responseHost = ref<HTMLElement>();
const requestEditor = sdk.ui.httpRequestEditor();
const responseEditor = sdk.ui.httpResponseEditor();
let timer: number | undefined;

onMounted(async () => {
  mountEditors();
  await load(0);
});
onUpdated(mountEditors);
watch(search, () => scheduleLoad(0));
watch(
  () => revision,
  async () => {
    await load(page.value.offset);
    if (selected.value !== undefined) {
      const current = await sdk.backend.getCandidate(selected.value.id);
      if (current !== undefined) hydrate(current);
    }
  },
);

function scheduleLoad(offset: number) {
  if (timer !== undefined) window.clearTimeout(timer);
  timer = window.setTimeout(() => {
    timer = undefined;
    void load(offset);
  }, 250);
}

async function load(offset: number) {
  loading.value = true;
  try {
    page.value = await sdk.backend.listCandidates({
      search: search.value,
      status: "ALL",
      severity: "ALL",
      offset,
      limit: page.value.limit,
    });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    loading.value = false;
  }
}

function hydrate(candidate: CandidateDTO) {
  selected.value = candidate;
  baselineRequestId.value = candidate.baselineRequestId ?? "";
  variantRequestId.value = candidate.variantRequestId ?? "";
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

async function attach(slot: "BASELINE" | "VARIANT") {
  if (selected.value === undefined) return;
  const requestId =
    slot === "BASELINE" ? baselineRequestId.value : variantRequestId.value;
  if (requestId.trim() === "") {
    sdk.window.showToast(`Enter a ${slot.toLowerCase()} Request ID.`, {
      variant: "warning",
    });
    return;
  }
  const accepted = await confirm({
    title: `Attach ${slot === "BASELINE" ? "Account A" : "Account B"}`,
    message:
      "Attach this saved in-scope exchange? WSTG Flow only reads the existing request and response.",
    confirmLabel: "Attach evidence",
  });
  if (!accepted) return;
  await run(
    async () =>
      sdk.backend.attachEvidence(selected.value!.id, requestId.trim(), slot),
    `${slot} evidence attached.`,
  );
}

async function clearEvidence() {
  if (selected.value === undefined) return;
  const accepted = await confirm({
    title: "Clear verification evidence",
    message: "Clear both Account A and Account B evidence links?",
    confirmLabel: "Clear evidence",
    danger: true,
  });
  if (!accepted) return;
  await run(async () => {
    await sdk.backend.clearEvidence(selected.value!.id);
    baselineRequestId.value = "";
    variantRequestId.value = "";
  });
}

async function run(action: () => Promise<unknown>, success?: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    if (selected.value !== undefined) {
      const current = await sdk.backend.getCandidate(selected.value.id);
      if (current !== undefined) hydrate(current);
    }
    if (success !== undefined)
      sdk.window.showToast(success, { variant: "success" });
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
    <div class="wstg-warning strong">
      Run both account requests manually in Replay first. WSTG Flow only links
      saved in-scope exchanges and compares them; it never sends A/B requests.
    </div>
    <div class="wstg-toolbar">
      <input
        v-model="search"
        class="wstg-input grow"
        aria-label="Search verification candidates"
        placeholder="Search candidate to verify…"
      />
    </div>
    <div class="wstg-table-wrap compact" :aria-busy="loading">
      <table class="wstg-table">
        <thead>
          <tr>
            <th>Candidate</th>
            <th>Endpoint</th>
            <th>A/B state</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="candidate in page.items"
            :key="candidate.id"
            :class="{ selected: selected?.id === candidate.id }"
          >
            <td>
              <button class="wstg-row-button" @click="hydrate(candidate)">
                {{ candidate.title }}
              </button>
            </td>
            <td>{{ candidate.method }} {{ candidate.url }}</td>
            <td>
              {{
                candidate.comparison
                  ? statusLabel(candidate.comparison.outcome)
                  : "not compared"
              }}
            </td>
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
      <h2>{{ selected.title }}</h2>
      <div class="wstg-verification-grid">
        <label>
          <span>Baseline / Account A Request ID</span>
          <input v-model="baselineRequestId" class="wstg-input" />
          <button
            class="wstg-button primary"
            :disabled="busy"
            @click="attach('BASELINE')"
          >
            Attach Account A
          </button>
        </label>
        <label>
          <span>Variant / Account B Request ID</span>
          <input v-model="variantRequestId" class="wstg-input" />
          <button
            class="wstg-button primary"
            :disabled="busy"
            @click="attach('VARIANT')"
          >
            Attach Account B
          </button>
        </label>
      </div>
      <article
        v-if="selected.comparison"
        class="wstg-comparison"
        :class="selected.comparison.outcome.toLowerCase()"
      >
        <h2>{{ statusLabel(selected.comparison.outcome) }}</h2>
        <pre>{{ selected.comparison.summary }}</pre>
      </article>
      <div v-else class="wstg-empty">
        Attach both exchanges to compare status, content, identity material,
        headers, and structured JSON differences.
      </div>
      <div class="wstg-toolbar">
        <button
          class="wstg-button"
          :disabled="!selected.baselineRequestId"
          @click="
            selected.baselineRequestId &&
            showMessage(selected.baselineRequestId)
          "
        >
          View Account A
        </button>
        <button
          class="wstg-button"
          :disabled="!selected.variantRequestId"
          @click="
            selected.variantRequestId && showMessage(selected.variantRequestId)
          "
        >
          View Account B
        </button>
        <button
          class="wstg-button danger"
          :disabled="busy"
          @click="clearEvidence"
        >
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
  </section>
</template>
