<script setup lang="ts">
import type { AssetDTO, Page } from "backend";
import { onMounted, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import { useSDK } from "@/plugins/sdk";
import { formatDate, safeMessage } from "@/utils";

const { revision } = defineProps<{ revision: number }>();
const sdk = useSDK();
const page = ref<Page<AssetDTO>>({ items: [], total: 0, offset: 0, limit: 50 });
const search = ref("");
const loading = ref(false);
let timer: number | undefined;

onMounted(() => load(0));
watch(search, () => scheduleLoad(0));
watch(
  () => revision,
  () => scheduleLoad(page.value.offset),
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
    page.value = await sdk.backend.listAssets({
      search: search.value,
      offset,
      limit: page.value.limit,
    });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <section class="wstg-content">
    <div class="wstg-warning">
      Assets are extracted passively from existing responses. WSTG Flow never
      fetches discovered URLs or source maps.
    </div>
    <div class="wstg-toolbar">
      <input
        v-model="search"
        class="wstg-input grow"
        aria-label="Search assets"
        placeholder="Search kind, URL, source…"
      />
    </div>
    <div class="wstg-table-wrap tall" :aria-busy="loading">
      <table class="wstg-table">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Discovered URL</th>
            <th>Source</th>
            <th>Discovered</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="asset in page.items" :key="asset.id">
            <td>{{ asset.kind }}</td>
            <td>{{ asset.url }}</td>
            <td>{{ asset.sourceUrl }}</td>
            <td>{{ formatDate(asset.discoveredAt) }}</td>
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
    <div v-if="!loading && page.total === 0" class="wstg-empty">
      No assets match the current search.
    </div>
  </section>
</template>
