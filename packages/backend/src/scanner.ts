import type { SDK } from "caido:plugin";
import type { Request, Response } from "caido:utils";

import { compareMessages } from "./comparator";
import { analyze, parseParameters } from "./detector";
import { mutateRequest } from "./mutator";
import { buildReport } from "./report";
import { WstgStore } from "./store";
import type {
  AssetDTO,
  AssetQuery,
  CandidateDTO,
  CandidateQuery,
  CandidateStatus,
  CheckStatus,
  DataArea,
  FindingDTO,
  FindingQuery,
  MessageDetails,
  Overview,
  Page,
  ReportFile,
  ReportFormat,
  ScanState,
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
  private readonly activeByGeneration = new Map<number, number>();
  private revision = 0;
  private readonly pendingAreas = new Set<DataArea>();
  private changeScheduled = false;

  async initialize(sdk: WstgSDK): Promise<void> {
    await this.store.initialize(sdk);
    this.settings = await this.store.getSettings();
    sdk.events.onInterceptResponse((_eventSDK, request, response) => {
      void this.observe(sdk, request, response);
    });
    sdk.events.onProjectChange((_eventSDK, project) => {
      this.monitorSince = new Date();
      if (project === null) this.cancel(sdk, "No active Caido project");
      else if (
        this.requireSettings().analysisEnabled &&
        this.requireSettings().autoHistory
      )
        void this.rescan(sdk, false);
      else this.resetRuntime(sdk, "Monitoring new responses");
    });
    if (this.settings.analysisEnabled && this.settings.autoHistory)
      await this.rescan(sdk, false);
    else
      this.resetRuntime(
        sdk,
        this.settings.analysisEnabled
          ? "Monitoring new responses"
          : "Automatic passive analysis disabled",
      );
    this.startMonitor(sdk);
  }

  async getOverview(sdk: WstgSDK): Promise<Overview> {
    const projectId = await this.currentProjectId(sdk);
    const settings = this.requireSettings();
    if (projectId === undefined)
      return {
        tests: [],
        recentCandidates: [],
        summary: {
          candidateTotal: 0,
          newCandidateCount: 0,
          findingTotal: 0,
          assetTotal: 0,
          testedCount: 0,
          passCount: 0,
          failCount: 0,
        },
        settings,
        state: { ...this.state, message: "No active Caido project" },
      };
    const overview = await this.store.overview(projectId);
    return {
      ...overview,
      settings,
      state: this.copyState(),
    };
  }

  async listCandidates(
    sdk: WstgSDK,
    query: CandidateQuery,
  ): Promise<Page<CandidateDTO>> {
    return this.store.listCandidates(await this.requireProjectId(sdk), query);
  }

  async listAssets(sdk: WstgSDK, query: AssetQuery): Promise<Page<AssetDTO>> {
    return this.store.listAssets(await this.requireProjectId(sdk), query);
  }

  async listFindings(
    sdk: WstgSDK,
    query: FindingQuery,
  ): Promise<Page<FindingDTO>> {
    return this.store.listFindings(await this.requireProjectId(sdk), query);
  }

  async getCandidate(
    sdk: WstgSDK,
    id: string,
  ): Promise<CandidateDTO | undefined> {
    return this.store.getCandidate(await this.requireProjectId(sdk), id);
  }

  async exportReport(sdk: WstgSDK, format: ReportFormat): Promise<ReportFile> {
    const projectId = await this.requireProjectId(sdk);
    const [tests, candidates, findings, assets] = await Promise.all([
      this.store.tests(projectId),
      this.store.candidates(projectId),
      this.store.findings(projectId),
      this.store.assets(projectId),
    ]);
    return buildReport(format, { tests, candidates, findings, assets });
  }

  async getMessage(
    sdk: WstgSDK,
    requestId: string,
  ): Promise<MessageDetails | undefined> {
    const pair = await sdk.requests.get(requestId);
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
    this.cancel(
      sdk,
      this.settings.analysisEnabled
        ? "Settings saved; scan History to apply them to existing traffic"
        : "Settings saved; automatic passive analysis disabled",
    );
    this.scheduleDataChanged(sdk, "overview");
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
    this.scheduleDataChanged(sdk, "overview", "candidates");
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
    this.scheduleDataChanged(sdk, "overview");
  }

  async analyzeRequest(sdk: WstgSDK, requestId: string): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const pair = await sdk.requests.get(requestId);
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
    this.scheduleDataChanged(sdk, "overview", "candidates", "assets");
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
    const pair = await sdk.requests.get(requestId);
    if (pair === undefined || pair.response === undefined)
      throw new Error("Verification evidence requires a saved response");
    if (!sdk.requests.inScope(pair.request))
      throw new Error("Verification evidence must remain in Caido Scope");
    assertComparisonSize(pair.request, pair.response, this.requireSettings());
    const baselineId =
      slot === "BASELINE" ? requestId : candidate.baselineRequestId;
    const variantId =
      slot === "VARIANT" ? requestId : candidate.variantRequestId;
    let comparison;
    if (baselineId !== undefined && variantId !== undefined) {
      if (baselineId === variantId)
        throw new Error(
          "Account A and Account B must use different saved exchanges",
        );
      const baseline = await sdk.requests.get(baselineId);
      const variant = await sdk.requests.get(variantId);
      if (baseline?.response !== undefined && variant?.response !== undefined) {
        if (
          !sdk.requests.inScope(baseline.request) ||
          !sdk.requests.inScope(variant.request)
        )
          throw new Error(
            "Both verification exchanges must remain in Caido Scope",
          );
        assertComparisonSize(
          baseline.request,
          baseline.response,
          this.requireSettings(),
        );
        assertComparisonSize(
          variant.request,
          variant.response,
          this.requireSettings(),
        );
        comparison = compareMessages(
          baseline.request.getRaw().toText(),
          baseline.response.getRaw().toText(),
          variant.request.getRaw().toText(),
          variant.response.getRaw().toText(),
        );
      }
    }
    await this.store.attachEvidence(
      projectId,
      candidateId,
      requestId,
      slot,
      comparison,
    );
    this.scheduleDataChanged(sdk, "candidates");
  }

  async clearEvidence(sdk: WstgSDK, candidateId: string): Promise<void> {
    await this.store.clearEvidence(
      await this.requireProjectId(sdk),
      candidateId,
    );
    this.scheduleDataChanged(sdk, "candidates");
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
    const pair = await sdk.requests.get(candidate.requestId);
    if (pair === undefined) throw new Error("Source request is unavailable");
    if (!sdk.requests.inScope(pair.request))
      throw new Error("Out-of-scope requests are blocked");
    const spec = mutateRequest(
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
    const finding = await this.store.prepareFinding(projectId, candidate);
    if (!finding.published) {
      const pair = await sdk.requests.get(
        finding.requestId ?? candidate.requestId,
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
      await this.store.completePublishedFinding(projectId, candidate, finding);
    }
    this.scheduleDataChanged(sdk, "overview", "candidates", "findings");
  }

  async clearCandidates(sdk: WstgSDK): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    this.cancel(sdk, "Unconfirmed candidates cleared");
    await this.store.clearUnconfirmed(projectId);
    this.scheduleDataChanged(sdk, "overview", "candidates");
  }

  async rebuildCandidates(sdk: WstgSDK): Promise<void> {
    await this.rescan(sdk, true);
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
    this.paused = clear;
    this.state.scanned = 0;
    this.state.dropped = 0;
    this.state.phase = clear ? "PAUSED" : "SCANNING";
    this.state.message = clear
      ? "Waiting for active analysis before rebuilding candidates"
      : "Reading Caido HTTP History";
    this.publishState(sdk);
    this.scheduleDataChanged(sdk, "overview", "candidates", "assets");
    if (clear) {
      if (!(await this.waitForOlderWorkers(generation))) return;
      await this.store.clearUnconfirmed(projectId);
      if (generation !== this.generation) return;
      this.paused = false;
      this.state.phase = "SCANNING";
      this.state.message = "Reading Caido HTTP History";
      this.publishState(sdk);
    }
    void this.readHistory(sdk, projectId, generation);
  }

  pause(sdk: WstgSDK): void {
    if (this.state.phase !== "SCANNING") return;
    this.paused = true;
    this.state.phase = "PAUSED";
    this.state.message = "Passive analysis paused";
    this.publishState(sdk);
  }

  resume(sdk: WstgSDK): void {
    if (this.state.phase !== "PAUSED") return;
    this.paused = false;
    this.state.phase = "SCANNING";
    this.state.message = "Passive analysis resumed";
    this.publishState(sdk);
    this.pump(sdk);
    this.finishIfIdle(sdk);
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
    this.scheduleDataChanged(sdk, "overview");
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
        if (cursor !== undefined) query = query.after(cursor);
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
      const oldest = this.processed.values().next().value;
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
      this.activeByGeneration.set(
        work.generation,
        (this.activeByGeneration.get(work.generation) ?? 0) + 1,
      );
      this.syncState();
      void this.process(sdk, work)
        .catch((error) =>
          sdk.console.error(`WSTG Flow analysis failed: ${safeMessage(error)}`),
        )
        .finally(() => {
          this.activeWorkers -= 1;
          const remaining =
            (this.activeByGeneration.get(work.generation) ?? 1) - 1;
          if (remaining <= 0) this.activeByGeneration.delete(work.generation);
          else this.activeByGeneration.set(work.generation, remaining);
          this.syncState();
          this.publishState(sdk);
          this.pump(sdk);
          if (work.generation === this.generation) {
            this.scheduleDataChanged(sdk, "overview", "candidates", "assets");
            this.finishIfIdle(sdk);
          }
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
    if (work.generation !== this.generation) return;
    await this.store.addAnalysis(
      work.projectId,
      result.candidates,
      result.assets,
      settings.maxCandidates,
    );
    if (work.generation !== this.generation) return;
    this.state.scanned += 1;
  }

  private async waitForOlderWorkers(generation: number): Promise<boolean> {
    while (
      [...this.activeByGeneration].some(
        ([activeGeneration, count]) =>
          activeGeneration !== generation && count > 0,
      )
    ) {
      if (generation !== this.generation) return false;
      await sleep(20);
    }
    return generation === this.generation;
  }

  private finishIfIdle(sdk: WstgSDK): void {
    if (
      this.historyReading ||
      this.queue.length > 0 ||
      (this.activeByGeneration.get(this.generation) ?? 0) > 0
    )
      return;
    this.state.phase = "IDLE";
    this.state.message = `Passive analysis complete: ${this.state.scanned} responses analyzed`;
    this.syncState();
    this.publishState(sdk);
    this.scheduleDataChanged(sdk, "overview", "candidates", "assets");
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
    this.state.dropped = 0;
    this.syncState();
    this.publishState(sdk);
    this.scheduleDataChanged(sdk, "overview");
  }

  private syncState(): void {
    this.state.queued = this.queue.length;
    this.state.active = this.activeByGeneration.get(this.generation) ?? 0;
  }

  private publishState(sdk: WstgSDK): void {
    this.syncState();
    sdk.api.send("scan-state", this.copyState());
  }

  private copyState(): ScanState {
    return { ...this.state };
  }

  private scheduleDataChanged(sdk: WstgSDK, ...areas: DataArea[]): void {
    areas.forEach((area) => this.pendingAreas.add(area));
    if (this.changeScheduled) return;
    this.changeScheduled = true;
    setTimeout(() => {
      this.changeScheduled = false;
      if (this.pendingAreas.size === 0) return;
      this.revision += 1;
      const changedAreas = [...this.pendingAreas];
      this.pendingAreas.clear();
      sdk.api.send("data-changed", {
        revision: this.revision,
        areas: changedAreas,
      });
    }, 500);
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
    responseBytes: responseRaw.toBytes().length,
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

function assertComparisonSize(
  request: Request,
  response: Response,
  settings: WstgSettings,
): void {
  if (request.getRaw().toBytes().length > settings.maxRequestBytes)
    throw new Error(
      "Verification request exceeds the configured request limit",
    );
  if (response.getRaw().toBytes().length > settings.maxResponseBytes)
    throw new Error(
      "Verification response exceeds the configured response limit",
    );
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
