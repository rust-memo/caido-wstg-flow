import type {
  AnalyzerInput,
  AnalyzerParameter,
  Confidence,
  DetectedCandidate,
  Severity,
} from "./types";

type DetectedAsset = {
  url: string;
  sourceUrl: string;
  kind: string;
};

type AnalysisResult = {
  candidates: DetectedCandidate[];
  assets: DetectedAsset[];
};

type SecretRule = {
  id: string;
  title: string;
  severity: Severity;
  wstgId: string;
  pattern: RegExp;
};

const SECRET_RULES: SecretRule[] = [
  secret(
    "secret.aws_access_key",
    "AWS access key",
    "High",
    "WSTG-INFO-05",
    /(?:AKIA|ASIA)[A-Z0-9]{16}/g,
  ),
  secret(
    "secret.google_api",
    "Google API key",
    "High",
    "WSTG-INFO-05",
    /AIza[0-9A-Za-z_-]{35}/g,
  ),
  secret(
    "secret.github_token",
    "GitHub token",
    "High",
    "WSTG-INFO-05",
    /(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}/g,
  ),
  secret(
    "secret.slack_token",
    "Slack token",
    "High",
    "WSTG-INFO-05",
    /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  ),
  secret(
    "secret.stripe_live",
    "Stripe live secret key",
    "Critical",
    "WSTG-INFO-05",
    /sk_live_[A-Za-z0-9]{16,}/g,
  ),
  secret(
    "secret.sendgrid",
    "SendGrid API key",
    "High",
    "WSTG-INFO-05",
    /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
  ),
  secret(
    "secret.twilio",
    "Twilio API key",
    "High",
    "WSTG-INFO-05",
    /SK[0-9a-fA-F]{32}/g,
  ),
  secret(
    "secret.private_key",
    "Private key material",
    "Critical",
    "WSTG-CRYP-04",
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  ),
  secret(
    "secret.jwt",
    "JWT exposed in response",
    "Medium",
    "WSTG-SESS-10",
    /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  ),
  secret(
    "secret.basic_auth_url",
    "Credentials embedded in URL",
    "High",
    "WSTG-CRYP-03",
    /https?:\/\/[^\s/:]{2,}:[^\s/@]{2,}@[^\s]+/gi,
  ),
];

const ABSOLUTE_URL = /https?:\/\/[a-z0-9._:-]+(?:\/[^\s"'<>)]*)?/gi;
const RELATIVE_ENDPOINT =
  /["'`]((?:\/|\.\.\/)(?:api|v[0-9]+|admin|internal|debug|graphql|auth|oauth|users?|accounts?)[^"'`\s]*)["'`]/gi;
const SOURCE_MAP = /\/\/[#@] sourceMappingURL=([^\s]+)/gm;
const INTERNAL_ADDRESS =
  /(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})/;
const STACK_TRACE =
  /(stack trace|traceback \(most recent|at [a-z0-9_.$]+\([a-z0-9_]+\.java:\d+\))/i;
const VERBOSE_ERROR =
  /(sqlstate\[|java\.lang\.[a-z]+exception|uncaught exception|fatal error.{0,80} on line)/i;
const GENERIC_SECRET =
  /(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{20,})/gi;

export function analyze(input: AnalyzerInput): AnalysisResult {
  const candidates: DetectedCandidate[] = [];
  const assets: DetectedAsset[] = [];
  analyzeParameters(input, candidates);
  analyzeHeaders(input, candidates);
  analyzeBody(input, candidates, assets);
  return {
    candidates: deduplicate(candidates),
    assets: deduplicateAssets(assets),
  };
}

export function parseParameters(
  query: string,
  body: string,
  contentType: string,
  cookieHeaders: string[],
): AnalyzerParameter[] {
  const output = parseEncoded(query, "QUERY");
  const lower = contentType.toLowerCase();
  if (lower.includes("application/x-www-form-urlencoded"))
    output.push(...parseEncoded(body, "FORM"));
  if (lower.includes("json")) collectJSON(body, output);
  for (const header of cookieHeaders)
    output.push(...parseEncoded(header.replace(/;\s*/g, "&"), "COOKIE"));
  return output.slice(0, 2_000);
}

function analyzeParameters(
  input: AnalyzerInput,
  output: DetectedCandidate[],
): void {
  for (const parameter of input.parameters) {
    const name = parameter.name.toLowerCase();
    if (
      parameter.location === "QUERY" &&
      isSessionName(name) &&
      parameter.value.length >= 12
    ) {
      const candidate = parameterCandidate(
        input,
        parameter,
        "param.session_url",
        "Session token exposed in URL",
        "Session",
        "Medium",
        "Firm",
        "WSTG-SESS-04",
        "A session or authentication token is present in the URL, where it can leak through logs, browser history, and referrers.",
        "Confirm that the value grants or resumes a session, then move it to a protected cookie or authorization header.",
      );
      candidate.payloads = [];
      output.push(candidate);
    }
    if (
      name === "__proto__" ||
      name === "constructor.prototype" ||
      name.includes("[__proto__]") ||
      name.includes("[prototype]")
    )
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.prototype_pollution",
          "Prototype pollution key in request",
          "Injection",
          "Medium",
          "Tentative",
          "WSTG-INPV-22",
          "A prototype-mutating key reached the application in captured traffic.",
          "Use a unique harmless property and verify whether it appears on unrelated objects without causing persistent changes.",
          "WSTGFLOW_MARKER",
        ),
      );
    if (
      exact(
        name,
        "id",
        "uid",
        "user_id",
        "account",
        "account_id",
        "object",
        "order",
        "invoice",
        "tenant",
        "org_id",
      )
    )
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.object_reference",
          "Possible IDOR/BOLA parameter",
          "Authorization",
          "Medium",
          "Tentative",
          "WSTG-ATHZ-04",
          "An identifier-like parameter may reference an object without adequate authorization.",
          "Repeat using two authorized accounts and substitute an identifier owned by the other account.",
          "1",
          "2",
          "../1",
        ),
      );
    if (
      contains(name, "redirect", "return", "next", "continue", "dest") &&
      confirmedExternalRedirect(input, parameter.value)
    )
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.redirect",
          "Observed external redirect parameter",
          "Open redirect",
          "Medium",
          "Firm",
          "WSTG-CLNT-04",
          "The captured redirect response points to the external destination supplied by this parameter.",
          "Repeat with a controlled HTTPS origin and verify the final Location/navigation target.",
          "https://example.org/",
          "//example.org/",
        ),
      );
    else if (
      contains(name, "url", "uri", "callback", "target", "feed", "webhook")
    )
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.url",
          "URL-controlled parameter",
          "SSRF / Redirect",
          "Medium",
          "Tentative",
          "WSTG-INPV-19",
          "A URL-like parameter may reach a redirect or server-side fetch sink.",
          "Determine whether navigation is client-side or fetched by the server; use a controlled benign endpoint.",
          "https://example.org/",
          "//example.org/",
        ),
      );
    if (
      contains(
        name,
        "file",
        "path",
        "folder",
        "dir",
        "template",
        "page",
        "include",
        "document",
        "download",
      )
    )
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.path",
          "File/path-controlled parameter",
          "Path traversal",
          "Medium",
          "Tentative",
          "WSTG-ATHZ-01",
          "A path-like parameter may influence filesystem access.",
          "Use a harmless known file and encoding variants; do not target sensitive files without authorization.",
          "../README.txt",
          "..%2fREADME.txt",
        ),
      );
    if (
      contains(name, "q", "query", "search", "filter", "sort", "where", "sql")
    )
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.query",
          "Query/search parameter",
          "Injection",
          "Low",
          "Tentative",
          "WSTG-INPV-05",
          "Search and filter values frequently reach query builders.",
          "Compare syntax-error, boolean, and time-neutral inputs in Replay.",
          "'",
          "' OR '1'='1",
          '"',
        ),
      );
    if (contains(name, "cmd", "exec", "command", "shell", "ping", "host"))
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.command",
          "Command-like parameter",
          "Command injection",
          "High",
          "Tentative",
          "WSTG-INPV-12",
          "The parameter name suggests it may be passed to a system or diagnostic command.",
          "Begin with non-destructive metacharacter and response-difference checks.",
          ";echo WSTGFLOW",
          "|echo WSTGFLOW",
        ),
      );
    if (
      contains(
        name,
        "html",
        "message",
        "comment",
        "name",
        "title",
        "description",
        "template",
        "content",
      )
    )
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.rendered",
          "Potential rendered-input parameter",
          "XSS / Template injection",
          "Low",
          "Tentative",
          "WSTG-INPV-01",
          "User-controlled text may be rendered into HTML or a template context.",
          "Inject a unique alphanumeric marker first, locate reflection, and choose a payload for its exact context.",
          "WSTGFLOW123",
          "<wstgflow>",
          "{{7*7}}",
        ),
      );
    if (
      contains(
        name,
        "role",
        "isadmin",
        "admin",
        "permission",
        "price",
        "amount",
        "status",
        "verified",
        "balance",
      )
    )
      output.push(
        parameterCandidate(
          input,
          parameter,
          "param.privileged",
          "Security-sensitive business parameter",
          "Mass assignment / Logic",
          "Medium",
          "Tentative",
          "WSTG-INPV-20",
          "Client-controlled security or business state deserves authorization and integrity review.",
          "Remove and modify the field in Replay using a test account; verify server-side enforcement.",
          "false",
          "true",
          "0",
        ),
      );
  }
  const path = input.path.toLowerCase();
  if (/\/(?:admin|internal|debug|actuator|swagger|api-docs)(?:\/|$)/.test(path))
    output.push(
      baseCandidate(
        input,
        "url.sensitive_path",
        "Sensitive or administrative endpoint",
        "Information gathering",
        "Information",
        "Firm",
        "WSTG-CONF-05",
        path,
        "Verify authentication, authorization, and production exposure.",
      ),
    );
  if (
    /\/graphql\/?$/i.test(path) ||
    (input.requestBody.includes('"query"') &&
      input.requestBody.toLowerCase().includes("graphql"))
  )
    output.push(
      baseCandidate(
        input,
        "api.graphql",
        "GraphQL endpoint observed",
        "API reconnaissance",
        "Information",
        "Firm",
        "WSTG-APIT-99",
        path,
        "Review schema exposure, resolver/object authorization, query depth, and batching controls.",
      ),
    );
}

function analyzeHeaders(
  input: AnalyzerInput,
  output: DetectedCandidate[],
): void {
  if (
    input.url.startsWith("https://") &&
    header(input.responseHeaders, "strict-transport-security") === ""
  )
    output.push(
      baseCandidate(
        input,
        "header.hsts",
        "Missing HSTS header",
        "Configuration",
        "Low",
        "Firm",
        "WSTG-CONF-07",
        "Strict-Transport-Security absent",
        "Confirm across the HTTPS host and review max-age/subdomain policy.",
      ),
    );
  const origin = header(input.headers, "origin");
  const allowOrigin = header(
    input.responseHeaders,
    "access-control-allow-origin",
  );
  if (
    origin !== "" &&
    allowOrigin === origin &&
    header(
      input.responseHeaders,
      "access-control-allow-credentials",
    ).toLowerCase() === "true" &&
    crossOrigin(origin, input.url)
  )
    output.push(
      baseCandidate(
        input,
        "header.cors",
        "Credentialed cross-origin request allowed",
        "CORS",
        "Medium",
        "Firm",
        "WSTG-CLNT-07",
        `Access-Control-Allow-Origin reflects ${origin}`,
        "Verify the allowlist using another controlled origin and confirm whether sensitive authenticated data is readable.",
      ),
    );
  const server = header(input.responseHeaders, "server");
  if (/\d+\.\d+/.test(server))
    output.push(
      baseCandidate(
        input,
        "header.server_version",
        "Server version disclosure",
        "Information gathering",
        "Information",
        "Firm",
        "WSTG-INFO-02",
        server,
        "Confirm the value is stable and not a deceptive banner.",
      ),
    );
  const responseType = input.responseContentType.toLowerCase();
  const csp = header(
    input.responseHeaders,
    "content-security-policy",
  ).toLowerCase();
  const xFrame = header(input.responseHeaders, "x-frame-options");
  if (
    input.statusCode >= 200 &&
    input.statusCode < 300 &&
    responseType.includes("text/html") &&
    xFrame === "" &&
    !csp.includes("frame-ancestors")
  )
    output.push(
      baseCandidate(
        input,
        "header.clickjacking",
        "Page may be frameable (clickjacking)",
        "Client-side",
        "Low",
        "Tentative",
        "WSTG-CLNT-09",
        "HTML response lacks X-Frame-Options and CSP frame-ancestors",
        "Confirm that the page renders in a cross-origin frame and contains a security-sensitive action before reporting.",
      ),
    );
  for (const cookie of headers(input.responseHeaders, "set-cookie")) {
    const name = cookie.split("=", 1)[0] ?? "cookie";
    if (!isSessionName(name.toLowerCase())) continue;
    const lower = cookie.toLowerCase();
    if (input.url.startsWith("https://") && !lower.includes("; secure"))
      output.push(cookieCandidate(input, name, "secure", "Secure"));
    if (!lower.includes("; httponly"))
      output.push(cookieCandidate(input, name, "httponly", "HttpOnly"));
    if (!lower.includes("; samesite"))
      output.push(cookieCandidate(input, name, "samesite", "SameSite"));
  }
}

function analyzeBody(
  input: AnalyzerInput,
  output: DetectedCandidate[],
  assets: DetectedAsset[],
): void {
  const body = input.responseBody;
  if (body === "") return;
  for (const rule of SECRET_RULES) {
    let count = 0;
    for (const match of body.matchAll(rule.pattern)) {
      if (count++ >= 10) break;
      const found = match[0];
      const candidate = baseCandidate(
        input,
        rule.id,
        rule.title,
        "Secret / Information leak",
        rule.severity,
        "Firm",
        rule.wstgId,
        `${mask(found)} at response offset ${match.index}`,
        "Validate the token type and revoke or rotate it only through the asset owner if confirmed.",
      );
      output.push(candidate);
    }
  }
  let genericCount = 0;
  for (const match of body.matchAll(GENERIC_SECRET)) {
    if (genericCount++ >= 10) break;
    const token = match[1] ?? "";
    const entropy = shannonEntropy(token);
    if (entropy < 3.5) continue;
    output.push(
      baseCandidate(
        input,
        "secret.high_entropy",
        "High-entropy token in client content",
        "Secret / Information leak",
        "Medium",
        "Tentative",
        "WSTG-INFO-05",
        `${mask(token)} (entropy ${entropy.toFixed(2)})`,
        "Identify the token type and privileges without using it against third-party systems.",
      ),
    );
  }
  const trace = STACK_TRACE.exec(body);
  const verbose = trace === null ? VERBOSE_ERROR.exec(body) : null;
  if (trace !== null)
    output.push(
      baseCandidate(
        input,
        "response.stack_trace",
        "Stack trace disclosed",
        "Error handling",
        "Low",
        "Firm",
        "WSTG-ERRH-02",
        context(body, trace.index, trace[0].length),
        "Reproduce with benign malformed input and determine whether internal code paths are exposed.",
      ),
    );
  else if (verbose !== null)
    output.push(
      baseCandidate(
        input,
        "response.verbose_error",
        "Verbose application error",
        "Error handling",
        "Low",
        "Firm",
        "WSTG-ERRH-01",
        context(body, verbose.index, verbose[0].length),
        "Reproduce with benign malformed input and determine whether internals are exposed.",
      ),
    );
  const internal = INTERNAL_ADDRESS.exec(body);
  if (internal !== null)
    output.push(
      baseCandidate(
        input,
        "response.internal_address",
        "Internal network address disclosed",
        "Information gathering",
        "Information",
        "Firm",
        "WSTG-INFO-05",
        internal[0],
        "Confirm it belongs to private infrastructure and assess whether it expands attack-surface knowledge.",
      ),
    );
  if (!isJavaScript(input)) return;
  let count = 0;
  for (const match of body.matchAll(SOURCE_MAP)) {
    if (count++ >= 20) break;
    const value = match[1] ?? "";
    assets.push({
      url: resolveURL(input.url, value),
      sourceUrl: input.url,
      kind: "Source map",
    });
    output.push(
      baseCandidate(
        input,
        "js.source_map",
        "JavaScript source map referenced",
        "JavaScript intelligence",
        "Information",
        "Firm",
        "WSTG-INFO-05",
        value,
        "Fetch only if it remains inside scope, then review original sources for secrets and hidden routes.",
      ),
    );
  }
  count = 0;
  for (const match of body.matchAll(ABSOLUTE_URL)) {
    if (count++ >= 200) break;
    assets.push({ url: match[0], sourceUrl: input.url, kind: "Absolute URL" });
  }
  count = 0;
  for (const match of body.matchAll(RELATIVE_ENDPOINT)) {
    if (count++ >= 200) break;
    assets.push({
      url: resolveURL(input.url, match[1] ?? ""),
      sourceUrl: input.url,
      kind: "JavaScript endpoint",
    });
  }
  if (
    /(?:innerHTML|outerHTML|document\.write|eval|setTimeout)\s*(?:=|\()/s.test(
      body,
    )
  )
    output.push(
      baseCandidate(
        input,
        "js.dom_sink",
        "Potential dangerous JavaScript sink",
        "Client-side injection",
        "Low",
        "Tentative",
        "WSTG-CLNT-01",
        "DOM sink found in JavaScript response",
        "Trace whether URL, postMessage, storage, or API data reaches the sink without context-appropriate encoding.",
      ),
    );
}

function parameterCandidate(
  input: AnalyzerInput,
  parameter: AnalyzerParameter,
  ruleId: string,
  title: string,
  category: string,
  severity: Severity,
  confidence: Confidence,
  wstgId: string,
  explanation: string,
  recommendedTest: string,
  ...payloads: string[]
): DetectedCandidate {
  return {
    ...baseCandidate(
      input,
      ruleId,
      title,
      category,
      severity,
      confidence,
      wstgId,
      `${parameter.name}=${mask(parameter.value)}`,
      recommendedTest,
    ),
    parameter: parameter.name,
    location: parameter.location,
    explanation,
    payloads,
  };
}

function baseCandidate(
  input: AnalyzerInput,
  ruleId: string,
  title: string,
  category: string,
  severity: Severity,
  confidence: Confidence,
  wstgId: string,
  evidence: string,
  recommendedTest: string,
): DetectedCandidate {
  return {
    requestId: input.requestId,
    responseId: input.responseId,
    ruleId,
    title,
    category,
    severity,
    confidence,
    url: redactURL(input.url),
    method: input.method,
    statusCode: input.statusCode,
    wstgId,
    parameter: "",
    location: "",
    evidence: clip(evidence, 1_000),
    explanation: `Detected by local rule ${ruleId}. Review context before confirming.`,
    recommendedTest,
    payloads: [],
  };
}

function cookieCandidate(
  input: AnalyzerInput,
  name: string,
  id: string,
  attribute: string,
): DetectedCandidate {
  const candidate = baseCandidate(
    input,
    `cookie.${id}`,
    `Session cookie missing ${attribute}: ${name}`,
    "Session",
    "Low",
    "Firm",
    "WSTG-SESS-02",
    `${name}=[REDACTED]`,
    `Review cross-site and script access requirements, then add an appropriate ${attribute} attribute.`,
  );
  candidate.parameter = name;
  candidate.location = "RESPONSE_HEADER";
  return candidate;
}

function parseEncoded(
  raw: string,
  location: AnalyzerParameter["location"],
): AnalyzerParameter[] {
  if (raw === "") return [];
  return raw.split("&").map((pair) => {
    const separator = pair.indexOf("=");
    return {
      name: safeDecode(separator < 0 ? pair : pair.slice(0, separator)),
      value: safeDecode(separator < 0 ? "" : pair.slice(separator + 1)),
      location,
    };
  });
}

function collectJSON(raw: string, output: AnalyzerParameter[]): void {
  let root: unknown;
  try {
    root = JSON.parse(raw) as unknown;
  } catch {
    return;
  }
  const walk = (value: unknown, depth: number): void => {
    if (depth > 25 || output.length >= 2_000 || value === null) return;
    if (Array.isArray(value)) {
      value.forEach((item) => walk(item, depth + 1));
      return;
    }
    if (typeof value !== "object") return;
    for (const [name, child] of Object.entries(value)) {
      if (["string", "number", "boolean"].includes(typeof child))
        output.push({ name, value: String(child), location: "JSON" });
      else walk(child, depth + 1);
    }
  };
  walk(root, 0);
}

function confirmedExternalRedirect(
  input: AnalyzerInput,
  value: string,
): boolean {
  const location = header(input.responseHeaders, "location");
  if (input.statusCode < 300 || input.statusCode >= 400 || location === "")
    return false;
  const decoded = safeDecode(value);
  return (
    (location === decoded || location.includes(decoded)) &&
    crossOrigin(location, input.url)
  );
}

function crossOrigin(origin: string, target: string): boolean {
  try {
    const a = new URL(origin, target);
    const b = new URL(target);
    return a.origin !== b.origin;
  } catch {
    return false;
  }
}

function resolveURL(base: string, path: string): string {
  try {
    return new URL(path, base).toString();
  } catch {
    return path;
  }
}

function header(values: Record<string, string[]>, name: string): string {
  return headers(values, name).join(", ");
}

function headers(values: Record<string, string[]>, name: string): string[] {
  const entry = Object.entries(values).find(
    ([key]) => key.toLowerCase() === name.toLowerCase(),
  );
  return entry?.[1] ?? [];
}

function isJavaScript(input: AnalyzerInput): boolean {
  return (
    input.path.toLowerCase().endsWith(".js") ||
    /(?:javascript|ecmascript)/i.test(input.responseContentType)
  );
}

function isSessionName(value: string): boolean {
  return /^(?:jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|(?:.*[_-])?(?:session(?:id)?|sess(?:id)?|sid|auth(?:token)?|access_token|refresh_token|token|jwt|sso)(?:[_-].*)?)$/i.test(
    value,
  );
}

function exact(value: string, ...needles: string[]): boolean {
  return needles.includes(value);
}

function contains(value: string, ...needles: string[]): boolean {
  return needles.some((needle) => value.includes(needle));
}

function mask(value: string): string {
  if (value.length < 8) return "[REDACTED]";
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

function context(value: string, index: number, length: number): string {
  let result = value
    .slice(
      Math.max(0, index - 100),
      Math.min(value.length, index + length + 100),
    )
    .replace(/[\r\n]+/g, " ");
  for (const rule of SECRET_RULES)
    result = result.replace(rule.pattern, (found) => mask(found));
  return result.replace(GENERIC_SECRET, (found, token: string) =>
    found.replace(token, mask(token)),
  );
}

function redactURL(value: string): string {
  return value.replace(/([?&][^=&#]+)=([^&#]*)/g, "$1=[REDACTED]");
}

function clip(value: string, maximum: number): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}…`;
}

function shannonEntropy(value: string): number {
  if (value === "") return 0;
  const counts = new Map<string, number>();
  for (const character of value)
    counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function deduplicate(values: DetectedCandidate[]): DetectedCandidate[] {
  const unique = new Map<string, DetectedCandidate>();
  for (const value of values) {
    const key = `${value.ruleId}\0${value.method}\0${value.url}\0${value.parameter}\0${value.location}`;
    if (!unique.has(key)) unique.set(key, value);
  }
  return [...unique.values()];
}

function deduplicateAssets(values: DetectedAsset[]): DetectedAsset[] {
  const unique = new Map<string, DetectedAsset>();
  for (const value of values) unique.set(`${value.kind}\0${value.url}`, value);
  return [...unique.values()];
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function secret(
  id: string,
  title: string,
  severity: Severity,
  wstgId: string,
  pattern: RegExp,
): SecretRule {
  return { id, title, severity, wstgId, pattern };
}
