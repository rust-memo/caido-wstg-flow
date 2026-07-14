import { createHash } from "crypto";

import type { SDK } from "caido:plugin";
import type { Database } from "sqlite";

import { validWstgId, WSTG_CATALOG } from "./catalog";
import type {
  AssetDTO,
  CandidateDTO,
  CandidateStatus,
  CheckStatus,
  ComparisonDTO,
  DetectedCandidate,
  FindingDTO,
  WstgSettings,
  WstgTestDTO,
} from "./types";

const DEFAULT_SETTINGS: WstgSettings = {
  analysisEnabled: true,
  scopeOnly: true,
  autoHistory: true,
  maxHistoryEntries: 5_000,
  maxCandidates: 3_000,
  maxRequestBytes: 1024 * 1024,
  maxResponseBytes: 5 * 1024 * 1024,
  ignoredHosts: [],
};

type CandidateRow = {
  project_id: string;
  id: string;
  fingerprint: string;
  request_id: string;
  response_id: string;
  created_at: string;
  last_seen: string;
  occurrence_count: number;
  rule_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  url: string;
  method: string;
  status_code: number;
  wstg_id: string;
  parameter_name: string;
  parameter_location: string;
  evidence: string;
  explanation: string;
  recommended_test: string;
  payloads_json: string;
  status: CandidateStatus;
  decision_notes: string;
  confirmed_finding_id?: string;
  baseline_request_id?: string;
  variant_request_id?: string;
  comparison_json: string;
  published: number;
};

type FindingRow = {
  project_id: string;
  id: string;
  candidate_id?: string;
  created_at: string;
  title: string;
  severity: string;
  confidence: string;
  url: string;
  method: string;
  status_code: number;
  wstg_id: string;
  comment: string;
  evidence: string;
  remediation: string;
  request_id?: string;
  published: number;
};

type AssetRow = {
  project_id: string;
  id: string;
  url: string;
  source_url: string;
  kind: string;
  discovered_at: string;
};

type ProgressRow = {
  wstg_id: string;
  status: CheckStatus;
  notes: string;
};

export class WstgStore {
  private database?: Database;

  async initialize(sdk: SDK): Promise<void> {
    if (this.database !== undefined) return;
    this.database = await sdk.meta.db();
    await this.database.exec(`
      CREATE TABLE IF NOT EXISTS wstg_candidates (
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        request_id TEXT NOT NULL,
        response_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        rule_id TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        url TEXT NOT NULL,
        method TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        wstg_id TEXT NOT NULL,
        parameter_name TEXT NOT NULL,
        parameter_location TEXT NOT NULL,
        evidence TEXT NOT NULL,
        explanation TEXT NOT NULL,
        recommended_test TEXT NOT NULL,
        payloads_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'NEW',
        decision_notes TEXT NOT NULL DEFAULT '',
        confirmed_finding_id TEXT,
        baseline_request_id TEXT,
        variant_request_id TEXT,
        comparison_json TEXT NOT NULL DEFAULT '',
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, id),
        UNIQUE(project_id, fingerprint)
      );
      CREATE INDEX IF NOT EXISTS wstg_candidates_status ON wstg_candidates(project_id, status, last_seen);
      CREATE TABLE IF NOT EXISTS wstg_findings (
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        candidate_id TEXT,
        created_at TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        url TEXT NOT NULL,
        method TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        wstg_id TEXT NOT NULL,
        comment TEXT NOT NULL,
        evidence TEXT NOT NULL,
        remediation TEXT NOT NULL,
        request_id TEXT,
        published INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(project_id, id)
      );
      CREATE INDEX IF NOT EXISTS wstg_findings_created ON wstg_findings(project_id, created_at);
      CREATE TABLE IF NOT EXISTS wstg_assets (
        project_id TEXT NOT NULL,
        id TEXT NOT NULL,
        url TEXT NOT NULL,
        source_url TEXT NOT NULL,
        kind TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        PRIMARY KEY(project_id, id)
      );
      CREATE TABLE IF NOT EXISTS wstg_progress (
        project_id TEXT NOT NULL,
        wstg_id TEXT NOT NULL,
        status TEXT NOT NULL,
        notes TEXT NOT NULL,
        PRIMARY KEY(project_id, wstg_id)
      );
      CREATE TABLE IF NOT EXISTS wstg_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
  }

  async getSettings(): Promise<WstgSettings> {
    const row = await this.requireDatabase()
      .prepare("SELECT value FROM wstg_settings WHERE key = ?")
      .then((statement) => statement.get<{ value: string }>("wstg-flow"));
    if (row === undefined) return cloneSettings(DEFAULT_SETTINGS);
    try {
      return normalizeSettings({
        ...DEFAULT_SETTINGS,
        ...(JSON.parse(row.value) as Partial<WstgSettings>),
      });
    } catch {
      return cloneSettings(DEFAULT_SETTINGS);
    }
  }

  async saveSettings(value: WstgSettings): Promise<WstgSettings> {
    const settings = normalizeSettings(value);
    const statement = await this.requireDatabase().prepare(
      "INSERT INTO wstg_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    );
    await statement.run("wstg-flow", JSON.stringify(settings));
    return settings;
  }

  async tests(projectId: string): Promise<WstgTestDTO[]> {
    const progress = await this.requireDatabase()
      .prepare("SELECT * FROM wstg_progress WHERE project_id = ?")
      .then((statement) => statement.all<ProgressRow>(projectId));
    const progressById = new Map(
      progress.map((value) => [value.wstg_id, value]),
    );
    const counts = await this.requireDatabase()
      .prepare(
        "SELECT wstg_id, COUNT(*) AS count FROM wstg_candidates WHERE project_id = ? AND status != 'REJECTED' GROUP BY wstg_id",
      )
      .then((statement) =>
        statement.all<{ wstg_id: string; count: number }>(projectId),
      );
    const countById = new Map(
      counts.map((value) => [value.wstg_id, value.count]),
    );
    return WSTG_CATALOG.map((test) => ({
      ...test,
      status: progressById.get(test.id)?.status ?? "NOT_TESTED",
      notes: progressById.get(test.id)?.notes ?? "",
      candidateCount: countById.get(test.id) ?? 0,
    }));
  }

  async candidates(projectId: string): Promise<CandidateDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM wstg_candidates WHERE project_id = ? ORDER BY last_seen DESC",
    );
    return (await statement.all<CandidateRow>(projectId)).map(toCandidate);
  }

  async findings(projectId: string): Promise<FindingDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM wstg_findings WHERE project_id = ? ORDER BY created_at DESC",
    );
    return (await statement.all<FindingRow>(projectId)).map(toFinding);
  }

  async assets(projectId: string): Promise<AssetDTO[]> {
    const statement = await this.requireDatabase().prepare(
      "SELECT * FROM wstg_assets WHERE project_id = ? ORDER BY discovered_at DESC",
    );
    return (await statement.all<AssetRow>(projectId)).map(toAsset);
  }

  async getCandidate(
    projectId: string,
    id: string,
  ): Promise<CandidateDTO | undefined> {
    const row = await this.requireDatabase()
      .prepare("SELECT * FROM wstg_candidates WHERE project_id = ? AND id = ?")
      .then((statement) => statement.get<CandidateRow>(projectId, id));
    return row === undefined ? undefined : toCandidate(row);
  }

  async addAnalysis(
    projectId: string,
    candidates: DetectedCandidate[],
    assets: Array<{ url: string; sourceUrl: string; kind: string }>,
    maximumCandidates: number,
  ): Promise<number> {
    let added = 0;
    for (const candidate of candidates) {
      const fingerprint = candidateFingerprint(candidate);
      const existing = await this.requireDatabase()
        .prepare(
          "SELECT id FROM wstg_candidates WHERE project_id = ? AND fingerprint = ?",
        )
        .then((statement) =>
          statement.get<{ id: string }>(projectId, fingerprint),
        );
      const now = new Date().toISOString();
      if (existing === undefined) {
        const count = await this.requireDatabase()
          .prepare(
            "SELECT COUNT(*) AS count FROM wstg_candidates WHERE project_id = ?",
          )
          .then((statement) => statement.get<{ count: number }>(projectId));
        if ((count?.count ?? 0) >= maximumCandidates) continue;
        const id = sha256(`${projectId}\n${fingerprint}`).slice(0, 24);
        const insert = await this.requireDatabase().prepare(`
          INSERT INTO wstg_candidates(
            project_id, id, fingerprint, request_id, response_id, created_at, last_seen,
            rule_id, title, category, severity, confidence, url, method, status_code,
            wstg_id, parameter_name, parameter_location, evidence, explanation,
            recommended_test, payloads_json
          ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        await insert.run(
          projectId,
          id,
          fingerprint,
          candidate.requestId,
          candidate.responseId,
          now,
          now,
          candidate.ruleId,
          candidate.title,
          candidate.category,
          candidate.severity,
          candidate.confidence,
          candidate.url,
          candidate.method,
          candidate.statusCode,
          candidate.wstgId,
          candidate.parameter,
          candidate.location,
          candidate.evidence,
          candidate.explanation,
          candidate.recommendedTest,
          JSON.stringify(candidate.payloads),
        );
        added += 1;
      } else {
        const update = await this.requireDatabase().prepare(`
          UPDATE wstg_candidates SET request_id = ?, response_id = ?, last_seen = ?,
            occurrence_count = occurrence_count + 1, status_code = ?, evidence = ?
          WHERE project_id = ? AND fingerprint = ?
        `);
        await update.run(
          candidate.requestId,
          candidate.responseId,
          now,
          candidate.statusCode,
          candidate.evidence,
          projectId,
          fingerprint,
        );
      }
    }
    for (const asset of assets) {
      const id = sha256(`${asset.kind}\n${asset.url}`).slice(0, 24);
      const statement = await this.requireDatabase().prepare(`
        INSERT OR IGNORE INTO wstg_assets(project_id, id, url, source_url, kind, discovered_at)
        VALUES(?, ?, ?, ?, ?, ?)
      `);
      await statement.run(
        projectId,
        id,
        clip(asset.url, 4_000),
        clip(asset.sourceUrl, 4_000),
        clip(asset.kind, 100),
        new Date().toISOString(),
      );
    }
    return added;
  }

  async updateCandidate(
    projectId: string,
    id: string,
    status: CandidateStatus,
    wstgId: string,
    notes: string,
  ): Promise<void> {
    if (!validWstgId(wstgId)) throw new Error("Unknown WSTG test ID");
    if (status === "CONFIRMED")
      throw new Error("Use Confirm finding to create a confirmed result");
    const statement = await this.requireDatabase().prepare(`
      UPDATE wstg_candidates SET status = ?, wstg_id = ?, decision_notes = ?
      WHERE project_id = ? AND id = ?
    `);
    await statement.run(
      status,
      wstgId,
      clip(notes.trim(), 8_000),
      projectId,
      id,
    );
  }

  async attachEvidence(
    projectId: string,
    candidateId: string,
    requestId: string,
    slot: "BASELINE" | "VARIANT",
    comparison: ComparisonDTO | undefined,
  ): Promise<void> {
    const column =
      slot === "BASELINE" ? "baseline_request_id" : "variant_request_id";
    const statement = await this.requireDatabase().prepare(`
      UPDATE wstg_candidates SET ${column} = ?, comparison_json = ?,
        status = CASE WHEN status = 'NEW' THEN 'REVIEWING' ELSE status END
      WHERE project_id = ? AND id = ?
    `);
    await statement.run(
      requestId,
      comparison === undefined ? "" : JSON.stringify(comparison),
      projectId,
      candidateId,
    );
  }

  async clearEvidence(projectId: string, candidateId: string): Promise<void> {
    const statement = await this.requireDatabase().prepare(`
      UPDATE wstg_candidates SET baseline_request_id = '', variant_request_id = '', comparison_json = ''
      WHERE project_id = ? AND id = ?
    `);
    await statement.run(projectId, candidateId);
  }

  async updateTest(
    projectId: string,
    wstgId: string,
    status: CheckStatus,
    notes: string,
  ): Promise<void> {
    if (!validWstgId(wstgId) || wstgId === "")
      throw new Error("Unknown WSTG test ID");
    const statement = await this.requireDatabase().prepare(`
      INSERT INTO wstg_progress(project_id, wstg_id, status, notes) VALUES(?, ?, ?, ?)
      ON CONFLICT(project_id, wstg_id) DO UPDATE SET status = excluded.status, notes = excluded.notes
    `);
    await statement.run(projectId, wstgId, status, clip(notes.trim(), 10_000));
  }

  async confirmCandidate(
    projectId: string,
    candidate: CandidateDTO,
  ): Promise<FindingDTO> {
    if (
      candidate.status === "CONFIRMED" &&
      candidate.confirmedFindingId !== undefined
    ) {
      const findingId = candidate.confirmedFindingId;
      const existing = await this.requireDatabase()
        .prepare("SELECT * FROM wstg_findings WHERE project_id = ? AND id = ?")
        .then((statement) => statement.get<FindingRow>(projectId, findingId));
      if (existing !== undefined) return toFinding(existing);
    }
    const id = sha256(`${projectId}\n${candidate.id}\nconfirmed`).slice(0, 24);
    const comparison = candidate.comparison?.summary ?? "";
    const finding: FindingDTO = {
      projectId,
      id,
      candidateId: candidate.id,
      createdAt: new Date().toISOString(),
      title: candidate.title,
      severity: candidate.severity,
      confidence: "Confirmed",
      url: candidate.url,
      method: candidate.method,
      statusCode: candidate.statusCode,
      wstgId: candidate.wstgId,
      comment: `${candidate.explanation}${candidate.decisionNotes === "" ? "" : `\n\nReviewer: ${candidate.decisionNotes}`}`,
      evidence: `${candidate.evidence}${comparison === "" ? "" : `\n\nVerification comparison:\n${comparison}`}`,
      remediation: "",
      requestId: candidate.variantRequestId ?? candidate.requestId,
      published: false,
    };
    const insert = await this.requireDatabase().prepare(`
      INSERT OR REPLACE INTO wstg_findings(
        project_id, id, candidate_id, created_at, title, severity, confidence, url,
        method, status_code, wstg_id, comment, evidence, remediation, request_id, published
      ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await insert.run(
      finding.projectId,
      finding.id,
      finding.candidateId ?? "",
      finding.createdAt,
      finding.title,
      finding.severity,
      finding.confidence,
      finding.url,
      finding.method,
      finding.statusCode,
      finding.wstgId,
      finding.comment,
      finding.evidence,
      finding.remediation,
      finding.requestId ?? "",
      0,
    );
    await this.requireDatabase()
      .prepare(
        "UPDATE wstg_candidates SET status = 'CONFIRMED', confirmed_finding_id = ? WHERE project_id = ? AND id = ?",
      )
      .then((statement) => statement.run(id, projectId, candidate.id));
    if (candidate.wstgId !== "")
      await this.updateTest(
        projectId,
        candidate.wstgId,
        "FAIL",
        "Confirmed finding recorded by WSTG Flow.",
      );
    return finding;
  }

  async markPublished(projectId: string, findingId: string): Promise<void> {
    await this.requireDatabase()
      .prepare(
        "UPDATE wstg_findings SET published = 1 WHERE project_id = ? AND id = ?",
      )
      .then((statement) => statement.run(projectId, findingId));
    await this.requireDatabase()
      .prepare(
        "UPDATE wstg_candidates SET published = 1 WHERE project_id = ? AND confirmed_finding_id = ?",
      )
      .then((statement) => statement.run(projectId, findingId));
  }

  async clearUnconfirmed(projectId: string): Promise<void> {
    await this.requireDatabase()
      .prepare(
        "DELETE FROM wstg_candidates WHERE project_id = ? AND status != 'CONFIRMED'",
      )
      .then((statement) => statement.run(projectId));
  }

  private requireDatabase(): Database {
    if (this.database === undefined)
      throw new Error("WSTG Flow database is not initialized");
    return this.database;
  }
}

function toCandidate(row: CandidateRow): CandidateDTO {
  return {
    projectId: row.project_id,
    id: row.id,
    fingerprint: row.fingerprint,
    requestId: row.request_id,
    responseId: row.response_id,
    createdAt: row.created_at,
    lastSeen: row.last_seen,
    occurrenceCount: row.occurrence_count,
    ruleId: row.rule_id,
    title: row.title,
    category: row.category,
    severity: row.severity,
    confidence: row.confidence,
    url: row.url,
    method: row.method,
    statusCode: row.status_code,
    wstgId: row.wstg_id,
    parameter: row.parameter_name,
    location: row.parameter_location,
    evidence: row.evidence,
    explanation: row.explanation,
    recommendedTest: row.recommended_test,
    payloads: parseStringArray(row.payloads_json),
    status: row.status,
    decisionNotes: row.decision_notes,
    confirmedFindingId: present(row.confirmed_finding_id),
    baselineRequestId: present(row.baseline_request_id),
    variantRequestId: present(row.variant_request_id),
    comparison: parseComparison(row.comparison_json),
    published: row.published === 1,
  };
}

function toFinding(row: FindingRow): FindingDTO {
  return {
    projectId: row.project_id,
    id: row.id,
    candidateId: present(row.candidate_id),
    createdAt: row.created_at,
    title: row.title,
    severity: row.severity,
    confidence: row.confidence,
    url: row.url,
    method: row.method,
    statusCode: row.status_code,
    wstgId: row.wstg_id,
    comment: row.comment,
    evidence: row.evidence,
    remediation: row.remediation,
    requestId: present(row.request_id),
    published: row.published === 1,
  };
}

function toAsset(row: AssetRow): AssetDTO {
  return {
    projectId: row.project_id,
    id: row.id,
    url: row.url,
    sourceUrl: row.source_url,
    kind: row.kind,
    discoveredAt: row.discovered_at,
  };
}

function candidateFingerprint(candidate: DetectedCandidate): string {
  const url = candidate.url.replace(/[?#].*$/, "");
  const hostScoped =
    candidate.ruleId.startsWith("header.") ||
    candidate.ruleId.startsWith("cookie.");
  return sha256(
    [
      candidate.ruleId,
      hostScoped ? "" : candidate.method,
      hostScoped ? origin(url) : url,
      candidate.parameter.toLowerCase(),
      candidate.location,
    ].join("|"),
  );
}

function origin(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return value;
  }
}

function normalizeSettings(value: WstgSettings): WstgSettings {
  return {
    analysisEnabled: value.analysisEnabled === true,
    scopeOnly: value.scopeOnly === true,
    autoHistory: value.autoHistory === true,
    maxHistoryEntries: bounded(value.maxHistoryEntries, 100, 50_000),
    maxCandidates: bounded(value.maxCandidates, 100, 20_000),
    maxRequestBytes: bounded(value.maxRequestBytes, 16_384, 10 * 1024 * 1024),
    maxResponseBytes: bounded(value.maxResponseBytes, 16_384, 20 * 1024 * 1024),
    ignoredHosts: [
      ...new Set(
        value.ignoredHosts
          .map((host) => host.trim().toLowerCase())
          .filter(Boolean),
      ),
    ].slice(0, 500),
  };
}

function cloneSettings(value: WstgSettings): WstgSettings {
  return { ...value, ignoredHosts: [...value.ignoredHosts] };
}

function bounded(value: number, minimum: number, maximum: number): number {
  return Number.isFinite(value)
    ? Math.max(minimum, Math.min(Math.round(value), maximum))
    : minimum;
}

function parseStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed)
      ? parsed.filter((item): item is string => typeof item === "string")
      : [];
  } catch {
    return [];
  }
}

function parseComparison(value: string): ComparisonDTO | undefined {
  if (value === "") return undefined;
  try {
    return JSON.parse(value) as ComparisonDTO;
  } catch {
    return undefined;
  }
}

function present(value: string | undefined): string | undefined {
  return value === undefined || value === "" ? undefined : value;
}

function clip(value: string, maximum: number): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
