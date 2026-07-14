export type CandidateStatus = "NEW" | "REVIEWING" | "CONFIRMED" | "REJECTED";
export type CheckStatus =
  "NOT_TESTED" | "IN_PROGRESS" | "PASS" | "FAIL" | "NOT_APPLICABLE";

export type WstgTestDTO = {
  category: string;
  id: string;
  name: string;
  commonName: string;
  reference: string;
  objectives: string;
  status: CheckStatus;
  notes: string;
  candidateCount: number;
};

export type ComparisonDTO = {
  outcome:
    | "SAME_CONTENT"
    | "ACCESS_DENIED"
    | "POSSIBLE_AUTHORIZATION_BYPASS"
    | "INCONCLUSIVE";
  baselineStatus: number;
  variantStatus: number;
  baselineLength: number;
  variantLength: number;
  similarity: number;
  identityDifferent: boolean;
  sameResource: boolean;
  jsonCompared: boolean;
  headerChanges: string[];
  jsonChanges: string[];
  summary: string;
};

export type CandidateDTO = {
  projectId: string;
  id: string;
  fingerprint: string;
  requestId: string;
  responseId: string;
  createdAt: string;
  lastSeen: string;
  occurrenceCount: number;
  ruleId: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  url: string;
  method: string;
  statusCode: number;
  wstgId: string;
  parameter: string;
  location: string;
  evidence: string;
  explanation: string;
  recommendedTest: string;
  payloads: string[];
  status: CandidateStatus;
  decisionNotes: string;
  confirmedFindingId?: string;
  baselineRequestId?: string;
  variantRequestId?: string;
  comparison?: ComparisonDTO;
  published: boolean;
};

export type FindingDTO = {
  projectId: string;
  id: string;
  candidateId?: string;
  createdAt: string;
  title: string;
  severity: string;
  confidence: string;
  url: string;
  method: string;
  statusCode: number;
  wstgId: string;
  comment: string;
  evidence: string;
  remediation: string;
  requestId?: string;
  published: boolean;
};

export type AssetDTO = {
  projectId: string;
  id: string;
  url: string;
  sourceUrl: string;
  kind: string;
  discoveredAt: string;
};

export type WstgSettings = {
  analysisEnabled: boolean;
  scopeOnly: boolean;
  autoHistory: boolean;
  maxHistoryEntries: number;
  maxCandidates: number;
  maxRequestBytes: number;
  maxResponseBytes: number;
  ignoredHosts: string[];
};

export type ScanState = {
  phase: "IDLE" | "SCANNING" | "PAUSED";
  queued: number;
  active: number;
  scanned: number;
  dropped: number;
  message: string;
};

export type Snapshot = {
  tests: WstgTestDTO[];
  candidates: CandidateDTO[];
  findings: FindingDTO[];
  assets: AssetDTO[];
  settings: WstgSettings;
  state: ScanState;
};

export type MessageDetails = {
  requestId: string;
  request: string;
  response: string;
};

export type AnalyzerParameter = {
  name: string;
  value: string;
  location: string;
};

export type AnalyzerInput = {
  requestId: string;
  responseId: string;
  method: string;
  url: string;
  host: string;
  path: string;
  query: string;
  headers: Record<string, string[]>;
  parameters: AnalyzerParameter[];
  requestRaw: string;
  requestBody: string;
  requestContentType: string;
  statusCode: number;
  responseHeaders: Record<string, string[]>;
  responseRaw: string;
  responseBody: string;
  responseContentType: string;
};

export type DetectedCandidate = Omit<
  CandidateDTO,
  | "projectId"
  | "id"
  | "fingerprint"
  | "createdAt"
  | "lastSeen"
  | "occurrenceCount"
  | "status"
  | "decisionNotes"
  | "confirmedFindingId"
  | "baselineRequestId"
  | "variantRequestId"
  | "comparison"
  | "published"
>;
