export type CandidateStatus = "NEW" | "REVIEWING" | "CONFIRMED" | "REJECTED";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Information";
export type Confidence = "Tentative" | "Firm" | "Confirmed";
export type ParameterLocation =
  "" | "QUERY" | "FORM" | "JSON" | "COOKIE" | "RESPONSE_HEADER";
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
  severity: Severity;
  confidence: Confidence;
  url: string;
  method: string;
  statusCode: number;
  wstgId: string;
  parameter: string;
  location: ParameterLocation;
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
  severity: Severity;
  confidence: Confidence;
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

export type ProjectSummary = {
  candidateTotal: number;
  newCandidateCount: number;
  findingTotal: number;
  assetTotal: number;
  testedCount: number;
  passCount: number;
  failCount: number;
};

export type Overview = {
  tests: WstgTestDTO[];
  recentCandidates: CandidateDTO[];
  summary: ProjectSummary;
  settings: WstgSettings;
  state: ScanState;
};

export type CandidateQuery = {
  search: string;
  status: "ALL" | CandidateStatus;
  severity: "ALL" | Severity;
  offset: number;
  limit: number;
};

export type AssetQuery = {
  search: string;
  offset: number;
  limit: number;
};

export type FindingQuery = {
  offset: number;
  limit: number;
};

export type Page<T> = {
  items: T[];
  total: number;
  offset: number;
  limit: number;
};

export type DataArea = "overview" | "candidates" | "assets" | "findings";

export type DataChanged = {
  revision: number;
  areas: DataArea[];
};

export type ReportFormat = "html" | "json" | "csv";

export type ReportFile = {
  filename: string;
  mediaType: string;
  content: string;
};

export type MessageDetails = {
  requestId: string;
  request: string;
  response: string;
};

export type AnalyzerParameter = {
  name: string;
  value: string;
  location: Exclude<ParameterLocation, "" | "RESPONSE_HEADER">;
};

export type AnalyzerInput = {
  requestId: string;
  responseId: string;
  responseBytes: number;
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
