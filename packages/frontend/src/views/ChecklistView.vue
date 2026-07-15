<script setup lang="ts">
import type { CheckStatus, WstgTestDTO } from "backend";
import { computed, ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { safeMessage, statusLabel } from "@/utils";

const { tests } = defineProps<{ tests: WstgTestDTO[] }>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const search = ref("");
const filter = ref("ALL");
const selectedId = ref("");
const status = ref<CheckStatus>("NOT_TESTED");
const notes = ref("");
const busy = ref(false);

const filtered = computed(() => {
  const query = search.value.trim().toLowerCase();
  return tests.filter((test) => {
    const haystack =
      `${test.id} ${test.category} ${test.name} ${test.commonName} ${test.objectives}`.toLowerCase();
    return (
      (filter.value === "ALL" || test.status === filter.value) &&
      (query === "" || haystack.includes(query))
    );
  });
});
const selected = computed(() =>
  tests.find((test) => test.id === selectedId.value),
);

function select(test: WstgTestDTO) {
  selectedId.value = test.id;
  status.value = test.status;
  notes.value = test.notes;
}

async function save() {
  if (selected.value === undefined || busy.value) return;
  busy.value = true;
  try {
    await sdk.backend.updateTest(selected.value.id, status.value, notes.value);
    sdk.window.showToast(`${selected.value.id} updated.`, {
      variant: "success",
    });
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
    <div class="wstg-toolbar">
      <input
        v-model="search"
        class="wstg-input grow"
        aria-label="Search WSTG checklist"
        placeholder="Search WSTG ID, category, test, objective…"
      />
      <select
        v-model="filter"
        class="wstg-select"
        aria-label="Checklist status"
      >
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
            v-for="test in filtered"
            :key="test.id"
            :class="{ selected: selectedId === test.id }"
          >
            <td>
              <button class="wstg-row-button" @click="select(test)">
                <code>{{ test.id }}</code>
              </button>
            </td>
            <td>{{ test.category }}</td>
            <td>{{ test.name }}</td>
            <td>{{ test.candidateCount }}</td>
            <td>{{ statusLabel(test.status) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <article v-if="selected" class="wstg-detail">
      <div class="wstg-detail-head">
        <div>
          <h2>{{ selected.id }} · {{ selected.name }}</h2>
          <p>{{ selected.category }}</p>
        </div>
        <a
          class="wstg-button"
          :href="selected.reference"
          target="_blank"
          rel="noreferrer"
        >
          OWASP reference
        </a>
      </div>
      <p class="wstg-objectives">
        {{
          selected.objectives || "No objective text in the bundled snapshot."
        }}
      </p>
      <div class="wstg-form-row">
        <label>
          <span>Status</span>
          <select v-model="status" class="wstg-select">
            <option>NOT_TESTED</option>
            <option>IN_PROGRESS</option>
            <option>PASS</option>
            <option>FAIL</option>
            <option>NOT_APPLICABLE</option>
          </select>
        </label>
        <label class="grow">
          <span>Tester notes</span>
          <textarea v-model="notes" class="wstg-textarea short" />
        </label>
        <button class="wstg-button primary" :disabled="busy" @click="save">
          Save progress
        </button>
      </div>
    </article>
  </section>
</template>
