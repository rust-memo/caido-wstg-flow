import type { SDK } from "caido:plugin";
import type { Cursor, ID, Request, RequestSpec, Response } from "caido:utils";

import { compareMessages } from "./comparator";
import { analyze, parseParameters } from "./detector";
import { WstgStore } from "./store";
import type {
  CandidateStatus,
  CheckStatus,
  MessageDetails,
  ScanState,
  Snapshot,
  WstgSettings,
} from "./types";

import type { BackendEvents } from "./index";

export type WstgSDK = SDK<Record<string, never>, BackendEvents>;

type Work = {
  generation: number;
  projectId: string;
  request: Request;
  response: Response;
};

export class WstgScanner {
  private readonly store = new WstgStore();
  private settings?: WstgSettings;
  private state: ScanState = {
    phase: "IDLE",
    queued: 0,
    active: 0,
    scanned: 0,
    dropped: 0,
    message: "Idle",
  };
  private readonly queue: Work[] = [];
  private readonly processed = new Set<string>();
  private generation = 0;
  private historyReading = false;
  private paused = false;
  private monitorStarted = false;
  private monitorSince = new Date();
  private activeWorkers = 0;

  async initialize(sdk: WstgSDK): Promise<void> {
    await this.store.initialize(sdk);
    this.settings = await this.store.getSettings();
    sdk.events.onInterceptResponse((_eventSDK, request, response) => {
      void this.observe(sdk, request, response);
    });
    sdk.events.onProjectChange((_eventSDK, project) => {
      this.monitorSince = new Date();
      if (project === null) this.cancel(sdk, "No active Caido project");
      else if (this.requireSettings().autoHistory) void this.rescan(sdk, false);
      else this.resetRuntime(sdk, "Monitoring new responses");
    });
    if (this.settings.autoHistory) await this.rescan(sdk, false);
    else this.resetRuntime(sdk, "Monitoring new responses");
    this.startMonitor(sdk);
  }

  async getSnapshot(sdk: WstgSDK): Promise<Snapshot> {
    const projectId = await this.currentProjectId(sdk);
    const settings = this.requireSettings();
    if (projectId === undefined)
      return {
        tests: [],
        candidates: [],
        findings: [],
        assets: [],
        settings,
        state: { ...this.state, message: "No active Caido project" },
      };
    const [tests, candidates, findings, assets] = await Promise.all([
      this.store.tests(projectId),
      this.store.candidates(projectId),
      this.store.findings(projectId),
      this.store.assets(projectId),
    ]);
    return {
      tests,
      candidates,
      findings,
      assets,
      settings,
      state: this.copyState(),
    };
  }

  async getMessage(
    sdk: WstgSDK,
    requestId: string,
  ): Promise<MessageDetails | undefined> {
    const pair = await sdk.requests.get(requestId as ID);
    if (pair === undefined) return undefined;
    return {
      requestId,
      request: pair.request.getRaw().toText(),
      response: pair.response?.getRaw().toText() ?? "",
    };
  }

  async saveSettings(sdk: WstgSDK, value: WstgSettings): Promise<WstgSettings> {
    this.settings = await this.store.saveSettings(value);
    this.monitorSince = new Date();
    await this.rescan(sdk, true);
    return this.settings;
  }

  async updateCandidate(
    sdk: WstgSDK,
    id: string,
    status: CandidateStatus,
    wstgId: string,
    notes: string,
  ): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    if ((await this.store.getCandidate(projectId, id)) === undefined)
      throw new Error("Candidate no longer exists");
    await this.store.updateCandidate(projectId, id, status, wstgId, notes);
    this.emitSnapshot(sdk);
  }

  async updateTest(
    sdk: WstgSDK,
    wstgId: string,
    status: CheckStatus,
    notes: string,
  ): Promise<void> {
    await this.store.updateTest(
      await this.requireProjectId(sdk),
      wstgId,
      status,
      notes,
    );
    this.emitSnapshot(sdk);
  }

  async analyzeRequest(sdk: WstgSDK, requestId: string): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const pair = await sdk.requests.get(requestId as ID);
    if (pair === undefined || pair.response === undefined)
      throw new Error("A saved request and response are required");
    if (this.requireSettings().scopeOnly && !sdk.requests.inScope(pair.request))
      throw new Error("Out-of-scope requests are blocked");
    await this.process(sdk, {
      generation: this.generation,
      projectId,
      request: pair.request,
      response: pair.response,
    });
    this.emitSnapshot(sdk);
  }

  async attachEvidence(
    sdk: WstgSDK,
    candidateId: string,
    requestId: string,
    slot: "BASELINE" | "VARIANT",
  ): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const candidate = await this.store.getCandidate(projectId, candidateId);
    if (candidate === undefined) throw new Error("Candidate no longer exists");
    const pair = await sdk.requests.get(requestId as ID);
    if (pair === undefined || pair.response === undefined)
      throw new Error("Verification evidence requires a saved response");
    if (!sdk.requests.inScope(pair.request))
      throw new Error("Verification evidence must remain in Caido Scope");
    const baselineId =
      slot === "BASELINE" ? requestId : candidate.baselineRequestId;
    const variantId =
      slot === "VARIANT" ? requestId : candidate.variantRequestId;
    let comparison;
    if (baselineId !== undefined && variantId !== undefined) {
      const baseline = await sdk.requests.get(baselineId as ID);
      const variant = await sdk.requests.get(variantId as ID);
      if (baseline?.response !== undefined && variant?.response !== undefined)
        comparison = compareMessages(
          baseline.request.getRaw().toText(),
          baseline.response.getRaw().toText(),
          variant.request.getRaw().toText(),
          variant.response.getRaw().toText(),
        );
    }
    await this.store.attachEvidence(
      projectId,
      candidateId,
      requestId,
      slot,
      comparison,
    );
    this.emitSnapshot(sdk);
  }

  async clearEvidence(sdk: WstgSDK, candidateId: string): Promise<void> {
    await this.store.clearEvidence(
      await this.requireProjectId(sdk),
      candidateId,
    );
    this.emitSnapshot(sdk);
  }

  async prepareReplay(
    sdk: WstgSDK,
    candidateId: string,
    payload: string,
  ): Promise<string> {
    const projectId = await this.requireProjectId(sdk);
    const candidate = await this.store.getCandidate(projectId, candidateId);
    if (candidate === undefined) throw new Error("Candidate no longer exists");
    if (!candidate.payloads.includes(payload))
      throw new Error("Use one of the bounded payload suggestions");
    if (candidate.parameter === "")
      throw new Error(
        "This candidate has no automatically replaceable parameter",
      );
    const pair = await sdk.requests.get(candidate.requestId as ID);
    if (pair === undefined) throw new Error("Source request is unavailable");
    if (!sdk.requests.inScope(pair.request))
      throw new Error("Out-of-scope requests are blocked");
    const spec = mutate(
      pair.request.toSpec(),
      candidate.parameter,
      candidate.location,
      payload,
    );
    if (!sdk.requests.inScope(spec))
      throw new Error("Modified request left Caido Scope");
    const session = await sdk.replay.createSession(spec);
    return session.getId();
  }

  async confirmAndPublish(sdk: WstgSDK, candidateId: string): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const candidate = await this.store.getCandidate(projectId, candidateId);
    if (candidate === undefined) throw new Error("Candidate no longer exists");
    if (candidate.status === "REJECTED")
      throw new Error("Rejected candidates must be moved to Reviewing first");
    const finding = await this.store.confirmCandidate(projectId, candidate);
    if (!finding.published) {
      const pair = await sdk.requests.get(
        (finding.requestId ?? candidate.requestId) as ID,
      );
      if (pair === undefined) throw new Error("Finding request is unavailable");
      await sdk.findings.create({
        title: finding.title,
        description:
          `${finding.comment}\n\nEvidence:\n${finding.evidence}\n\n` +
          `WSTG: ${finding.wstgId || "Unmapped"}\n` +
          `Endpoint: ${finding.method} ${finding.url}\n\n` +
          `This description omits authentication material. Review the associated existing Caido request according to project data-handling rules.`,
        reporter: "WSTG Flow",
        dedupeKey: `wstg-flow:${finding.id}`,
        request: pair.request,
      });
      await this.store.markPublished(projectId, finding.id);
    }
    this.emitSnapshot(sdk);
  }

  async clearCandidates(sdk: WstgSDK): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    this.cancel(sdk, "Unconfirmed candidates cleared");
    await this.store.clearUnconfirmed(projectId);
    this.emitSnapshot(sdk);
  }

  async rescan(sdk: WstgSDK, clear: boolean): Promise<void> {
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) {
      this.cancel(sdk, "No active Caido project");
      return;
    }
    this.generation += 1;
    const generation = this.generation;
    this.queue.length = 0;
    this.processed.clear();
    this.historyReading = true;
    this.paused = false;
    this.state.scanned = 0;
    this.state.phase = "SCANNING";
    this.state.message = "Reading Caido HTTP History";
    if (clear) await this.store.clearUnconfirmed(projectId);
    this.publishState(sdk);
    this.emitSnapshot(sdk);
    void this.readHistory(sdk, projectId, generation);
  }

  pause(sdk: WstgSDK): void {
    this.paused = true;
    this.state.phase = "PAUSED";
    this.state.message = "Passive analysis paused";
    this.publishState(sdk);
  }

  resume(sdk: WstgSDK): void {
    this.paused = false;
    this.state.phase = "SCANNING";
    this.state.message = "Passive analysis resumed";
    this.publishState(sdk);
    this.pump(sdk);
  }

  cancel(sdk: WstgSDK, message = "Queued work cancelled"): void {
    this.generation += 1;
    this.queue.length = 0;
    this.historyReading = false;
    this.paused = false;
    this.state.phase = "IDLE";
    this.state.message = message;
    this.syncState();
    this.publishState(sdk);
  }

  private async readHistory(
    sdk: WstgSDK,
    projectId: string,
    generation: number,
  ): Promise<void> {
    const settings = this.requireSettings();
    let cursor: string | undefined;
    let inspected = 0;
    try {
      while (
        inspected < settings.maxHistoryEntries &&
        generation === this.generation
      ) {
        const amount = Math.min(200, settings.maxHistoryEntries - inspected);
        let query = sdk.requests
          .query()
          .descending("req", "created_at")
          .first(amount);
        if (cursor !== undefined) query = query.after(cursor as Cursor);
        const page = await query.execute();
        if (page.items.length === 0) break;
        for (const item of page.items) {
          if (generation !== this.generation) return;
          inspected += 1;
          if (item.response === undefined) continue;
          if (settings.scopeOnly && !sdk.requests.inScope(item.request))
            continue;
          this.enqueue(sdk, {
            generation,
            projectId,
            request: item.request,
            response: item.response,
          });
          while (this.queue.length > 100 && generation === this.generation)
            await sleep(20);
        }
        if (!page.pageInfo.hasNextPage) break;
        cursor = page.pageInfo.endCursor;
      }
      if (generation === this.generation)
        this.state.message = `Queued ${inspected} recent History entries`;
    } catch (error) {
      this.state.message = `History scan failed: ${safeMessage(error)}`;
      sdk.console.error(this.state.message);
    } finally {
      if (generation === this.generation) {
        this.historyReading = false;
        this.finishIfIdle(sdk);
      }
    }
  }

  private async observe(
    sdk: WstgSDK,
    request: Request,
    response: Response,
  ): Promise<void> {
    const settings = this.requireSettings();
    if (!settings.analysisEnabled || this.paused) return;
    if (settings.scopeOnly && !sdk.requests.inScope(request)) return;
    if (settings.ignoredHosts.includes(request.getHost().toLowerCase())) return;
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) return;
    this.enqueue(sdk, {
      generation: this.generation,
      projectId,
      request,
      response,
    });
  }

  private startMonitor(sdk: WstgSDK): void {
    if (this.monitorStarted) return;
    this.monitorStarted = true;
    void this.monitorRecentHistory(sdk);
  }

  private async monitorRecentHistory(sdk: WstgSDK): Promise<void> {
    while (this.monitorStarted) {
      await sleep(1_500);
      if (this.paused || !this.requireSettings().analysisEnabled) continue;
      try {
        const projectId = await this.currentProjectId(sdk);
        if (projectId === undefined) continue;
        const generation = this.generation;
        const settings = this.requireSettings();
        const page = await sdk.requests
          .query()
          .descending("req", "created_at")
          .first(Math.min(200, settings.maxHistoryEntries))
          .execute();
        if (generation !== this.generation) continue;
        for (const item of page.items) {
          if (item.response === undefined) continue;
          const key = `${projectId}:${item.request.getId()}`;
          if (this.processed.has(key)) continue;
          if (
            !settings.autoHistory &&
            item.request.getCreatedAt() < this.monitorSince
          )
            continue;
          if (settings.scopeOnly && !sdk.requests.inScope(item.request))
            continue;
          if (
            settings.ignoredHosts.includes(item.request.getHost().toLowerCase())
          )
            continue;
          this.enqueue(sdk, {
            generation,
            projectId,
            request: item.request,
            response: item.response,
          });
        }
      } catch (error) {
        sdk.console.error(`WSTG Flow monitor failed: ${safeMessage(error)}`);
      }
    }
  }

  private enqueue(sdk: WstgSDK, work: Work): void {
    const key = `${work.projectId}:${work.request.getId()}`;
    if (work.generation !== this.generation || this.processed.has(key)) return;
    this.processed.add(key);
    if (this.processed.size > this.requireSettings().maxHistoryEntries * 2) {
      const oldest = this.processed.values().next().value as string | undefined;
      if (oldest !== undefined) this.processed.delete(oldest);
    }
    if (this.queue.length >= 2_000) {
      this.state.dropped += 1;
      this.publishState(sdk);
      return;
    }
    this.queue.push(work);
    this.state.phase = this.paused ? "PAUSED" : "SCANNING";
    this.syncState();
    this.publishState(sdk);
    this.pump(sdk);
  }

  private pump(sdk: WstgSDK): void {
    if (this.paused) return;
    while (this.activeWorkers < 2 && this.queue.length > 0) {
      const work = this.queue.shift();
      if (work === undefined) break;
      this.activeWorkers += 1;
      this.syncState();
      void this.process(sdk, work)
        .catch((error) =>
          sdk.console.error(`WSTG Flow analysis failed: ${safeMessage(error)}`),
        )
        .finally(() => {
          this.activeWorkers -= 1;
          this.syncState();
          this.publishState(sdk);
          this.emitSnapshot(sdk);
          this.pump(sdk);
          this.finishIfIdle(sdk);
        });
    }
  }

  private async process(sdk: WstgSDK, work: Work): Promise<void> {
    if (work.generation !== this.generation) return;
    const settings = this.requireSettings();
    if (settings.ignoredHosts.includes(work.request.getHost().toLowerCase()))
      return;
    const input = toAnalyzerInput(work.request, work.response, settings);
    const result = analyze(input);
    await this.store.addAnalysis(
      work.projectId,
      result.candidates,
      result.assets,
      settings.maxCandidates,
    );
    this.state.scanned += 1;
  }

  private finishIfIdle(sdk: WstgSDK): void {
    if (this.historyReading || this.queue.length > 0 || this.activeWorkers > 0)
      return;
    this.state.phase = "IDLE";
    this.state.message = `Passive analysis complete: ${this.state.scanned} responses analyzed`;
    this.syncState();
    this.publishState(sdk);
    this.emitSnapshot(sdk);
  }

  private resetRuntime(sdk: WstgSDK, message: string): void {
    this.generation += 1;
    this.queue.length = 0;
    this.processed.clear();
    this.historyReading = false;
    this.paused = false;
    this.state.phase = "IDLE";
    this.state.message = message;
    this.state.scanned = 0;
    this.publishState(sdk);
  }

  private syncState(): void {
    this.state.queued = this.queue.length;
    this.state.active = this.activeWorkers;
  }

  private publishState(sdk: WstgSDK): void {
    this.syncState();
    sdk.api.send("scan-state", this.copyState());
  }

  private copyState(): ScanState {
    return { ...this.state };
  }

  private emitSnapshot(sdk: WstgSDK): void {
    void this.getSnapshot(sdk)
      .then((snapshot) => sdk.api.send("snapshot", snapshot))
      .catch((error) =>
        sdk.console.error(`WSTG Flow snapshot failed: ${safeMessage(error)}`),
      );
  }

  private requireSettings(): WstgSettings {
    if (this.settings === undefined)
      throw new Error("WSTG Flow settings are not initialized");
    return this.settings;
  }

  private async currentProjectId(sdk: WstgSDK): Promise<string | undefined> {
    return (await sdk.projects.getCurrent())?.getId();
  }

  private async requireProjectId(sdk: WstgSDK): Promise<string> {
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) throw new Error("No active Caido project");
    return projectId;
  }
}

function toAnalyzerInput(
  request: Request,
  response: Response,
  settings: WstgSettings,
) {
  const requestBody = request.getBody();
  const requestBodyRaw = requestBody?.toRaw();
  const body =
    requestBodyRaw !== undefined &&
    requestBodyRaw.length <= settings.maxRequestBytes
      ? (requestBody?.toText() ?? "")
      : "";
  const responseBody = response.getBody();
  const responseBodyRaw = responseBody?.toRaw();
  const responseText =
    responseBodyRaw !== undefined &&
    responseBodyRaw.length <= settings.maxResponseBytes &&
    isTextResponse(request, response)
      ? (responseBody?.toText() ?? "")
      : "";
  const requestContentType = (request.getHeader("Content-Type") ?? []).join(
    " ",
  );
  const requestRaw = request.getRaw();
  const responseRaw = response.getRaw();
  return {
    requestId: request.getId(),
    responseId: response.getId(),
    method: request.getMethod(),
    url: request.getUrl(),
    host: request.getHost(),
    path: request.getPath(),
    query: request.getQuery(),
    headers: request.getHeaders(),
    parameters: parseParameters(
      request.getQuery(),
      body,
      requestContentType,
      request.getHeader("Cookie") ?? [],
    ),
    requestRaw:
      requestRaw.toBytes().length <= settings.maxRequestBytes
        ? requestRaw.toText()
        : "[request exceeds configured limit]",
    requestBody: body,
    requestContentType,
    statusCode: response.getCode(),
    responseHeaders: response.getHeaders(),
    responseRaw:
      responseRaw.toBytes().length <= settings.maxResponseBytes
        ? responseRaw.toText()
        : "[response exceeds configured limit]",
    responseBody: responseText,
    responseContentType: (response.getHeader("Content-Type") ?? []).join(" "),
  };
}

function mutate(
  spec: RequestSpec,
  name: string,
  location: string,
  payload: string,
): RequestSpec {
  if (location === "QUERY") {
    spec.setQuery(replaceEncoded(spec.getQuery(), name, payload));
    return spec;
  }
  if (location === "FORM") {
    spec.setBody(
      replaceEncoded(spec.getBody()?.toText() ?? "", name, payload),
      { updateContentLength: true },
    );
    return spec;
  }
  if (location === "JSON") {
    spec.setBody(replaceJSON(spec.getBody()?.toText() ?? "", name, payload), {
      updateContentLength: true,
    });
    return spec;
  }
  if (location === "COOKIE") {
    const values = spec.getHeader("Cookie") ?? [];
    spec.setHeader(
      "Cookie",
      values.map((value) => replaceCookie(value, name, payload)).join("; "),
    );
    return spec;
  }
  throw new Error("This parameter location must be edited manually in Replay");
}

function replaceEncoded(raw: string, name: string, payload: string): string {
  let replaced = false;
  return raw
    .split("&")
    .map((pair) => {
      const separator = pair.indexOf("=");
      const rawName = separator < 0 ? pair : pair.slice(0, separator);
      if (!replaced && safeDecode(rawName) === name) {
        replaced = true;
        return `${rawName}=${encodeURIComponent(payload)}`;
      }
      return pair;
    })
    .join("&");
}

function replaceCookie(raw: string, name: string, payload: string): string {
  return raw
    .split(";")
    .map((part) => {
      const separator = part.indexOf("=");
      return (separator < 0 ? part : part.slice(0, separator)).trim() === name
        ? `${name}=${payload}`
        : part.trim();
    })
    .join("; ");
}

function replaceJSON(raw: string, name: string, payload: string): string {
  let root: unknown;
  try {
    root = JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
  let replaced = false;
  const walk = (value: unknown, depth: number): void => {
    if (replaced || depth > 25 || value === null || typeof value !== "object")
      return;
    if (Array.isArray(value)) {
      value.forEach((item) => walk(item, depth + 1));
      return;
    }
    for (const [key, child] of Object.entries(value)) {
      if (key === name) {
        (value as Record<string, unknown>)[key] = payload;
        replaced = true;
        return;
      }
      walk(child, depth + 1);
    }
  };
  walk(root, 0);
  return replaced ? JSON.stringify(root) : raw;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function isTextResponse(request: Request, response: Response): boolean {
  const contentType = (response.getHeader("Content-Type") ?? [])
    .join(" ")
    .toLowerCase();
  const path = request.getPath().toLowerCase();
  return !(
    /(image|audio|video|font|octet-stream|pdf|zip)/.test(contentType) ||
    /\.(?:png|jpe?g|gif|webp|avif|ico|woff2?|ttf|pdf|zip|gz)$/.test(path)
  );
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
