<script setup lang="ts">
import type { FindingDTO, Page } from "backend";
import { onMounted, onUpdated, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import { useSDK } from "@/plugins/sdk";
import { formatDate, safeMessage } from "@/utils";

const { revision } = defineProps<{ revision: number }>();
const sdk = useSDK();
const page = ref<Page<FindingDTO>>({
  items: [],
  total: 0,
  offset: 0,
  limit: 50,
});
const loading = ref(false);
const selected = ref<FindingDTO>();
const requestHost = ref<HTMLElement>();
const responseHost = ref<HTMLElement>();
const requestEditor = sdk.ui.httpRequestEditor();
const responseEditor = sdk.ui.httpResponseEditor();

onMounted(async () => {
  mountEditors();
  await load(0);
});
onUpdated(mountEditors);
watch(
  () => revision,
  () => load(page.value.offset),
);

async function load(offset: number) {
  loading.value = true;
  try {
    page.value = await sdk.backend.listFindings({
      offset,
      limit: page.value.limit,
    });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    loading.value = false;
  }
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

async function select(finding: FindingDTO) {
  selected.value = finding;
  if (finding.requestId === undefined) return;
  try {
    const message = await sdk.backend.getMessage(finding.requestId);
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
</script>

<template>
  <section class="wstg-content">
    <div class="wstg-warning">
      Only manually confirmed candidates appear here and in Caido Findings.
      Associated requests can still contain sensitive project data.
    </div>
    <div class="wstg-table-wrap" :aria-busy="loading">
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
            v-for="finding in page.items"
            :key="finding.id"
            :class="{ selected: selected?.id === finding.id }"
          >
            <td>
              <span class="wstg-badge" :class="`severity-${finding.severity}`">
                {{ finding.severity }}
              </span>
            </td>
            <td>
              <button class="wstg-row-button" @click="select(finding)">
                {{ finding.title }}
              </button>
            </td>
            <td>{{ finding.method }} {{ finding.url }}</td>
            <td>{{ finding.wstgId || "—" }}</td>
            <td>{{ formatDate(finding.createdAt) }}</td>
            <td>{{ finding.published ? "yes" : "no" }}</td>
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
      <p>{{ selected.comment }}</p>
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
    <div v-if="!loading && page.total === 0" class="wstg-empty">
      No confirmed findings.
    </div>
  </section>
</template>
