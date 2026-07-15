import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import { WstgScanner } from "./scanner";
import type { WstgSDK } from "./scanner";
import type {
  AssetDTO,
  AssetQuery,
  CandidateDTO,
  CandidateQuery,
  CandidateStatus,
  CheckStatus,
  DataChanged,
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

const scanner = new WstgScanner();
const assistantSDK = (sdk: SDK): WstgSDK => sdk;

const getOverview = (sdk: SDK): Promise<Overview> =>
  scanner.getOverview(assistantSDK(sdk));
const listCandidates = (
  sdk: SDK,
  query: CandidateQuery,
): Promise<Page<CandidateDTO>> =>
  scanner.listCandidates(assistantSDK(sdk), query);
const listAssets = (sdk: SDK, query: AssetQuery): Promise<Page<AssetDTO>> =>
  scanner.listAssets(assistantSDK(sdk), query);
const listFindings = (
  sdk: SDK,
  query: FindingQuery,
): Promise<Page<FindingDTO>> => scanner.listFindings(assistantSDK(sdk), query);
const getCandidate = (
  sdk: SDK,
  id: string,
): Promise<CandidateDTO | undefined> =>
  scanner.getCandidate(assistantSDK(sdk), id);
const exportReport = (sdk: SDK, format: ReportFormat): Promise<ReportFile> =>
  scanner.exportReport(assistantSDK(sdk), format);
const getMessage = (
  sdk: SDK,
  requestId: string,
): Promise<MessageDetails | undefined> =>
  scanner.getMessage(assistantSDK(sdk), requestId);
const saveSettings = (
  sdk: SDK,
  settings: WstgSettings,
): Promise<WstgSettings> => scanner.saveSettings(assistantSDK(sdk), settings);
const updateCandidate = (
  sdk: SDK,
  id: string,
  status: CandidateStatus,
  wstgId: string,
  notes: string,
): Promise<void> =>
  scanner.updateCandidate(assistantSDK(sdk), id, status, wstgId, notes);
const updateTest = (
  sdk: SDK,
  wstgId: string,
  status: CheckStatus,
  notes: string,
): Promise<void> =>
  scanner.updateTest(assistantSDK(sdk), wstgId, status, notes);
const analyzeRequest = (sdk: SDK, requestId: string): Promise<void> =>
  scanner.analyzeRequest(assistantSDK(sdk), requestId);
const attachEvidence = (
  sdk: SDK,
  candidateId: string,
  requestId: string,
  slot: "BASELINE" | "VARIANT",
): Promise<void> =>
  scanner.attachEvidence(assistantSDK(sdk), candidateId, requestId, slot);
const clearEvidence = (sdk: SDK, candidateId: string): Promise<void> =>
  scanner.clearEvidence(assistantSDK(sdk), candidateId);
const prepareReplay = (
  sdk: SDK,
  candidateId: string,
  payload: string,
): Promise<string> =>
  scanner.prepareReplay(assistantSDK(sdk), candidateId, payload);
const confirmAndPublish = (sdk: SDK, candidateId: string): Promise<void> =>
  scanner.confirmAndPublish(assistantSDK(sdk), candidateId);
const rescanHistory = (sdk: SDK): Promise<void> =>
  scanner.rescan(assistantSDK(sdk), false);
const rebuildCandidates = (sdk: SDK): Promise<void> =>
  scanner.rebuildCandidates(assistantSDK(sdk));
const clearCandidates = (sdk: SDK): Promise<void> =>
  scanner.clearCandidates(assistantSDK(sdk));
const pause = (sdk: SDK): void => scanner.pause(assistantSDK(sdk));
const resume = (sdk: SDK): void => scanner.resume(assistantSDK(sdk));
const cancel = (sdk: SDK): void => scanner.cancel(assistantSDK(sdk));

export type API = DefineAPI<{
  getOverview: typeof getOverview;
  listCandidates: typeof listCandidates;
  listAssets: typeof listAssets;
  listFindings: typeof listFindings;
  getCandidate: typeof getCandidate;
  exportReport: typeof exportReport;
  getMessage: typeof getMessage;
  saveSettings: typeof saveSettings;
  updateCandidate: typeof updateCandidate;
  updateTest: typeof updateTest;
  analyzeRequest: typeof analyzeRequest;
  attachEvidence: typeof attachEvidence;
  clearEvidence: typeof clearEvidence;
  prepareReplay: typeof prepareReplay;
  confirmAndPublish: typeof confirmAndPublish;
  rescanHistory: typeof rescanHistory;
  rebuildCandidates: typeof rebuildCandidates;
  clearCandidates: typeof clearCandidates;
  pause: typeof pause;
  resume: typeof resume;
  cancel: typeof cancel;
}>;

export type BackendEvents = DefineEvents<{
  "data-changed": (change: DataChanged) => void;
  "scan-state": (state: ScanState) => void;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.api.register("getOverview", getOverview);
  sdk.api.register("listCandidates", listCandidates);
  sdk.api.register("listAssets", listAssets);
  sdk.api.register("listFindings", listFindings);
  sdk.api.register("getCandidate", getCandidate);
  sdk.api.register("exportReport", exportReport);
  sdk.api.register("getMessage", getMessage);
  sdk.api.register("saveSettings", saveSettings);
  sdk.api.register("updateCandidate", updateCandidate);
  sdk.api.register("updateTest", updateTest);
  sdk.api.register("analyzeRequest", analyzeRequest);
  sdk.api.register("attachEvidence", attachEvidence);
  sdk.api.register("clearEvidence", clearEvidence);
  sdk.api.register("prepareReplay", prepareReplay);
  sdk.api.register("confirmAndPublish", confirmAndPublish);
  sdk.api.register("rescanHistory", rescanHistory);
  sdk.api.register("rebuildCandidates", rebuildCandidates);
  sdk.api.register("clearCandidates", clearCandidates);
  sdk.api.register("pause", pause);
  sdk.api.register("resume", resume);
  sdk.api.register("cancel", cancel);
  void scanner
    .initialize(assistantSDK(sdk))
    .catch((error) =>
      sdk.console.error(`WSTG Flow failed to initialize: ${String(error)}`),
    );
}

export type {
  AssetDTO,
  CandidateDTO,
  CandidateStatus,
  CheckStatus,
  ComparisonDTO,
  Confidence,
  DataArea,
  DataChanged,
  FindingDTO,
  FindingQuery,
  MessageDetails,
  Overview,
  Page,
  ParameterLocation,
  ProjectSummary,
  ReportFile,
  ReportFormat,
  ScanState,
  Severity,
  WstgSettings,
  WstgTestDTO,
} from "./types";
export type { AssetQuery, CandidateQuery } from "./types";
