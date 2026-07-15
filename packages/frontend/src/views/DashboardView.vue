<script setup lang="ts">
import type { Overview } from "backend";
import { ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { safeMessage, statusLabel } from "@/utils";

const { overview } = defineProps<{ overview: Overview }>();
const emit = defineEmits<{
  refresh: [];
  openCandidate: [id: string];
}>();
const sdk = useSDK();
const busy = ref(false);
const requestId = ref("");

async function run(action: () => Promise<unknown>, success?: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    if (success !== undefined)
      sdk.window.showToast(success, { variant: "success" });
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}

async function analyzeRequest() {
  const id = requestId.value.trim();
  if (id === "") {
    sdk.window.showToast("Enter a Caido Request ID with a saved response.", {
      variant: "warning",
    });
    return;
  }
  await run(
    async () => sdk.backend.analyzeRequest(id),
    "Selected request analyzed locally.",
  );
}
</script>

<template>
  <section class="wstg-content">
    <div class="wstg-dashboard-grid">
      <article class="wstg-stat hero">
        <span>WSTG coverage</span>
        <strong>
          {{
            overview.tests.length === 0
              ? 0
              : Math.round(
                  (overview.summary.testedCount / overview.tests.length) * 100,
                )
          }}%
        </strong>
        <small>
          {{ overview.summary.testedCount }} of
          {{ overview.tests.length }} tests reviewed
        </small>
      </article>
      <article class="wstg-stat">
        <span>Candidate inbox</span>
        <strong>{{ overview.summary.candidateTotal }}</strong>
        <small>{{ overview.summary.newCandidateCount }} awaiting review</small>
      </article>
      <article class="wstg-stat">
        <span>Confirmed findings</span>
        <strong>{{ overview.summary.findingTotal }}</strong>
        <small>{{ overview.summary.failCount }} WSTG tests marked fail</small>
      </article>
      <article class="wstg-stat">
        <span>Discovered assets</span>
        <strong>{{ overview.summary.assetTotal }}</strong>
        <small>URLs and endpoints are never fetched</small>
      </article>
    </div>
    <div class="wstg-warning">
      Candidates are workflow hints, not findings. Passive analysis sends no
      requests. Suggested payloads create Replay sessions only.
    </div>
    <div class="wstg-toolbar">
      <button
        class="wstg-button primary"
        :disabled="busy || overview.state.phase === 'SCANNING'"
        @click="run(() => sdk.backend.rescanHistory(), 'History scan started.')"
      >
        Scan History
      </button>
      <button
        class="wstg-button"
        :disabled="
          busy || !['SCANNING', 'PAUSED'].includes(overview.state.phase)
        "
        @click="
          run(() =>
            overview.state.phase === 'PAUSED'
              ? sdk.backend.resume()
              : sdk.backend.pause(),
          )
        "
      >
        {{ overview.state.phase === "PAUSED" ? "Resume" : "Pause" }}
      </button>
      <button
        class="wstg-button"
        :disabled="busy || overview.state.phase === 'IDLE'"
        @click="run(() => sdk.backend.cancel())"
      >
        Cancel queued
      </button>
      <input
        v-model="requestId"
        class="wstg-input grow"
        aria-label="Caido Request ID"
        placeholder="Caido Request ID for explicit local analysis"
      />
      <button class="wstg-button" :disabled="busy" @click="analyzeRequest">
        Analyze request
      </button>
    </div>
    <h2 class="wstg-section-title">Recent candidates</h2>
    <div v-if="overview.recentCandidates.length" class="wstg-table-wrap">
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
            v-for="candidate in overview.recentCandidates"
            :key="candidate.id"
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
              <button
                class="wstg-row-button"
                @click="emit('openCandidate', candidate.id)"
              >
                {{ candidate.title }}
              </button>
            </td>
            <td>{{ candidate.method }} {{ candidate.url }}</td>
            <td>{{ candidate.wstgId || "—" }}</td>
            <td>{{ candidate.occurrenceCount }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="wstg-empty">No candidates discovered yet.</div>
  </section>
</template>
