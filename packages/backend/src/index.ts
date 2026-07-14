import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import { WstgScanner } from "./scanner";
import type { WstgSDK } from "./scanner";
import type {
  CandidateStatus,
  CheckStatus,
  MessageDetails,
  ScanState,
  Snapshot,
  WstgSettings,
} from "./types";

const scanner = new WstgScanner();
const assistantSDK = (sdk: SDK): WstgSDK => sdk as unknown as WstgSDK;

const getSnapshot = (sdk: SDK): Promise<Snapshot> =>
  scanner.getSnapshot(assistantSDK(sdk));
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
const clearCandidates = (sdk: SDK): Promise<void> =>
  scanner.clearCandidates(assistantSDK(sdk));
const pause = (sdk: SDK): void => scanner.pause(assistantSDK(sdk));
const resume = (sdk: SDK): void => scanner.resume(assistantSDK(sdk));
const cancel = (sdk: SDK): void => scanner.cancel(assistantSDK(sdk));

export type API = DefineAPI<{
  getSnapshot: typeof getSnapshot;
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
  clearCandidates: typeof clearCandidates;
  pause: typeof pause;
  resume: typeof resume;
  cancel: typeof cancel;
}>;

export type BackendEvents = DefineEvents<{
  snapshot: (snapshot: Snapshot) => void;
  "scan-state": (state: ScanState) => void;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.api.register("getSnapshot", getSnapshot);
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
  FindingDTO,
  MessageDetails,
  ScanState,
  Snapshot,
  WstgSettings,
  WstgTestDTO,
} from "./types";
