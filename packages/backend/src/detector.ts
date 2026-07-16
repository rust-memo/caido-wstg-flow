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
  confidence: Confidence;
  wstgId: string;
  pattern: RegExp;
};

const SECRET_RULES: SecretRule[] = [
  secret(
    "secret.aws_access_key",
    "AWS access key identifier",
    "Medium",
    "WSTG-INFO-05",
    /(?:AKIA|ASIA)[A-Z0-9]{16}/g,
    "Tentative",
  ),
  secret(
    "secret.google_api",
    "Google API key",
    "Medium",
    "WSTG-INFO-05",
    /AIza[0-9A-Za-z_-]{35}/g,
    "Tentative",
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
    "Twilio API key identifier",
    "Low",
    "WSTG-INFO-05",
    /SK[0-9a-fA-F]{32}/g,
    "Tentative",
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
  /(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})/g;
const STACK_TRACE =
  /(stack trace|traceback \(most recent|at [a-z0-9_.$]+\([a-z0-9_]+\.java:\d+\))/i;
const VERBOSE_ERROR =
  /(sqlstate\[|java\.lang\.[a-z]+exception|uncaught exception|fatal error.{0,80} on line)/i;
const GENERIC_SECRET =
  /(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{20,})/gi;
const SQL_ERROR =
  /(?:sqlstate\[[0-9a-z]+]|you have an error in your sql syntax|unclosed quotation mark after the character string|pg_query\(|postgresql.{0,40}error|ora-\d{5}|sqlite(?:3)?(?:error|_exception)|jdbc(?:template)?[^\r\n]{0,60}exception)/i;
const PASSWORD_HASH =
  /(?:\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2(?:id|i|d)\$v=\d+\$[A-Za-z0-9+/=,$.-]{20,})/g;
const CARD_VALUE =
  /(?:card(?:_?number)?|primary_?account_?number|\bpan\b)\s*["']?\s*[:=]\s*["']?([0-9][0-9 -]{11,23}[0-9])/gi;
const REJECTION =
  /(?:not allowed|not permitted|unknown field|unexpected field|unrecogni[sz]ed field|validation failed|forbidden|access denied|permission denied|not found|does not exist|unauthori[sz]ed)/i;
const DOM_SINK =
  /(?:\.\s*(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.(?:write|writeln)\s*\(|(?:^|[^.\w])eval\s*\(|new\s+Function\s*\()/m;
const DOM_SOURCE =
  /(?:location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)|URLSearchParams\s*\(|(?:message|event)\.data|localStorage|sessionStorage)/;

const OBJECT_REFERENCE_NAMES = new Set([
  "id",
  "uid",
  "user_id",
  "account",
  "account_id",
  "object",
  "object_id",
  "order",
  "order_id",
  "invoice",
  "invoice_id",
  "tenant",
  "tenant_id",
  "org_id",
  "organization_id",
  "document_id",
  "record_id",
]);
const URL_PARAMETER_NAMES = new Set([
  "url",
  "uri",
  "link",
  "href",
  "src",
  "source",
  "target",
  "destination",
  "redirect",
  "redirect_uri",
  "return",
  "return_url",
  "next",
  "continue",
  "dest",
  "callback",
  "callback_url",
  "webhook",
  "webhook_url",
  "endpoint",
  "feed",
  "address",
]);
const REDIRECT_PARAMETER_NAMES = new Set([
  "redirect",
  "redirect_uri",
  "return",
  "return_url",
  "next",
  "continue",
  "dest",
  "destination",
]);
const PATH_PARAMETER_NAMES = new Set([
  "file",
  "filename",
  "filepath",
  "path",
  "folder",
  "directory",
  "dir",
  "template",
  "page",
  "include",
  "document",
  "download",
]);
const QUERY_PARAMETER_NAMES = new Set([
  "q",
  "query",
  "search",
  "filter",
  "sort",
  "where",
  "sql",
  "orderby",
  "order_by",
]);
const COMMAND_PARAMETER_NAMES = new Set(["cmd", "exec", "command", "shell"]);
const RENDERED_PARAMETER_NAMES = new Set([
  "html",
  "message",
  "comment",
  "name",
  "title",
  "description",
  "template",
  "content",
]);
const PRIVILEGED_PARAMETER_NAMES = new Set([
  "isadmin",
  "is_admin",
  "admin",
  "role",
  "roles",
  "permission",
  "permissions",
  "is_verified",
  "verified",
  "is_active",
  "account_status",
  "email_verified",
  "premium",
  "is_premium",
]);
const BUSINESS_PARAMETER_NAMES = new Set([
  "price",
  "unit_price",
  "amount",
  "balance",
  "credit",
  "discount",
  "total",
]);
const RATE_LIMIT_PREFIXES = ["x-ratelimit-", "x-rate-limit-", "ratelimit-"];
const ANTI_AUTOMATION_HEADERS = new Set([
  "retry-after",
  "x-captcha-required",
  "x-bot-detection",
]);
const ANTI_AUTOMATION_MARKERS = [
  "captcha",
  "recaptcha",
  "hcaptcha",
  "g-recaptcha",
  "turnstile",
  "challenge-platform",
  "cf-challenge",
];

export function analyze(input: AnalyzerInput): AnalysisResult {
  const candidates: DetectedCandidate[] = [];
  const assets: DetectedAsset[] = [];
  analyzeParameters(input, candidates);
  analyzeHeaders(input, candidates);
  analyzeApiSignals(input, candidates, assets);
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
      looksSessionToken(parameter.value)
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
    if (OBJECT_REFERENCE_NAMES.has(name) && looksIdentifier(parameter.value))
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
      REDIRECT_PARAMETER_NAMES.has(name) &&
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
    else if (isURLParameter(name) && looksURLValue(parameter.value))
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
    if (PATH_PARAMETER_NAMES.has(name) && looksPathValue(parameter.value))
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
    if (QUERY_PARAMETER_NAMES.has(name) && parameter.value.trim() !== "")
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
    if (isCommandParameter(input, name, parameter.value))
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
      RENDERED_PARAMETER_NAMES.has(name) &&
      reflectedInHTML(input, parameter.value)
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
      isModifyingMethod(input.method) &&
      (parameter.location === "JSON" || parameter.location === "FORM") &&
      (PRIVILEGED_PARAMETER_NAMES.has(name) ||
        BUSINESS_PARAMETER_NAMES.has(name))
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
  addDuplicateParameterCandidates(input, output);

  const path = input.path.toLowerCase();
  const pathIdentifier = objectIdentifierFromPath(path);
  if (pathIdentifier !== undefined)
    output.push(
      baseCandidate(
        input,
        "path.object_reference",
        "Object identifier observed in API path",
        "Authorization",
        "Medium",
        "Tentative",
        "WSTG-APIT-02",
        `Path contains object identifier ${mask(pathIdentifier)}`,
        "Use two authorized accounts and compare the same path after substituting an object identifier owned by the other account. A 2xx alone is not proof; compare object identity and rejection markers.",
      ),
    );
  if (
    isSuccessfulResponse(input) &&
    hasPathSegment(path, "admin", "internal", "debug", "actuator", "metrics")
  )
    output.push(
      baseCandidate(
        input,
        "url.sensitive_path",
        "Sensitive or management endpoint responded successfully",
        "Authorization / Inventory",
        "Low",
        "Tentative",
        "WSTG-APIT-04",
        `${input.method} ${path} returned ${input.statusCode}`,
        "Compare the saved exchange with a deliberately unauthenticated or lower-privilege request. Confirm response semantics; a successful status alone does not prove authorization bypass.",
      ),
    );
  if (isSuccessfulResponse(input) && looksDeprecatedPath(path))
    output.push(
      baseCandidate(
        input,
        "api.deprecated_version",
        "Deprecated or legacy API route observed",
        "API inventory",
        "Low",
        "Tentative",
        "WSTG-APIT-01",
        `${input.method} ${path} returned ${input.statusCode}`,
        "Confirm the route is outside its supported deprecation window and compare its authorization and response fields with the current API version.",
      ),
    );
  if (
    isSuccessfulResponse(input) &&
    isModifyingMethod(input.method) &&
    isSensitiveBusinessPath(path) &&
    !hasAntiAutomation(input)
  )
    output.push(
      baseCandidate(
        input,
        "api.sensitive_business_flow",
        "Sensitive business flow lacks visible anti-automation signals",
        "Business logic",
        "Information",
        "Tentative",
        "WSTG-BUSL-05",
        `${input.method} ${path}; no rate-limit, Retry-After, or CAPTCHA signal observed`,
        "Validate server-side rate limits and per-account business limits with an authorized test plan. Header absence alone is not proof that controls are missing.",
      ),
    );
  if (
    isSuccessfulResponse(input) &&
    ["POST", "PUT", "PATCH"].includes(input.method.toUpperCase()) &&
    isWebhookPath(path)
  )
    output.push(
      baseCandidate(
        input,
        "api.webhook_receiver",
        "Webhook receiver endpoint observed",
        "Unsafe API consumption",
        "Information",
        "Tentative",
        "WSTG-APIT-01",
        `${input.method} ${path} returned ${input.statusCode}`,
        "Verify provider signatures before parsing or side effects, enforce replay protection, validate the schema, and allow-list sources where appropriate.",
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
  analyzeAuthentication(input, output);
  if (
    input.url.startsWith("https://") &&
    !isLoopbackHost(input.host) &&
    input.statusCode < 500 &&
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
        "Observed credentialed CORS origin reflection",
        "CORS",
        "Medium",
        "Tentative",
        "WSTG-CLNT-07",
        `Access-Control-Allow-Origin reflects ${origin}`,
        "Repeat with a different controlled origin. Only report if an untrusted origin is accepted and sensitive authenticated data is readable; a legitimate allow-list can produce this single response.",
      ),
    );
  if (
    allowOrigin.trim() === "null" &&
    header(
      input.responseHeaders,
      "access-control-allow-credentials",
    ).toLowerCase() === "true"
  )
    output.push(
      baseCandidate(
        input,
        "header.cors_null",
        "Credentialed CORS trusts the null origin",
        "CORS",
        "Medium",
        "Firm",
        "WSTG-CLNT-07",
        "Access-Control-Allow-Origin: null with credentials enabled",
        "Confirm from a sandboxed controlled document that authenticated response data is readable, then replace null trust with an explicit origin allow-list.",
      ),
    );
  const server = header(input.responseHeaders, "server");
  if (/^[A-Za-z][A-Za-z0-9_. -]*\/\d+(?:\.\d+)+(?:[\s(].*)?$/.test(server))
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
  const poweredBy = header(input.responseHeaders, "x-powered-by");
  if (poweredBy.trim() !== "")
    output.push(
      baseCandidate(
        input,
        "header.technology",
        "Technology disclosure via X-Powered-By",
        "Information gathering",
        "Information",
        "Firm",
        "WSTG-INFO-08",
        `X-Powered-By: ${poweredBy}`,
        "Confirm the header is not required by clients, then remove it at the application or edge layer.",
      ),
    );
  const apiVersion =
    header(input.responseHeaders, "x-api-version") ||
    header(input.responseHeaders, "api-version");
  if (apiVersion.trim() !== "")
    output.push(
      baseCandidate(
        input,
        "header.api_version",
        "API version disclosed in response header",
        "API inventory",
        "Information",
        "Firm",
        "WSTG-APIT-01",
        `API version header: ${apiVersion}`,
        "Record the version in the API inventory and verify that unsupported versions are retired. Remove the header only if it has no client contract value.",
      ),
    );
  if (
    input.url.startsWith("http://") &&
    !isLoopbackHost(input.host) &&
    isSuccessfulResponse(input) &&
    requestCarriesCredentials(input)
  )
    output.push(
      baseCandidate(
        input,
        "header.cleartext_credentials",
        "Credentials transmitted over cleartext HTTP",
        "Authentication / Transport",
        "High",
        "Firm",
        "WSTG-ATHN-01",
        "A successful HTTP exchange contains authentication or credential material",
        "Serve the endpoint exclusively over HTTPS and redirect cleartext requests before reading credentials. Rotate exposed credentials when appropriate.",
      ),
    );
  if (
    input.method.toUpperCase() === "TRACE" &&
    input.statusCode === 200 &&
    traceResponseEchoesRequest(input)
  )
    output.push(
      baseCandidate(
        input,
        "header.trace_echo",
        "HTTP TRACE echoed the request",
        "Configuration",
        "Medium",
        "Confirmed",
        "WSTG-CONF-06",
        "TRACE returned 200 and echoed request material in the response body",
        "Disable TRACE at the edge and origin unless it is explicitly required.",
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
    isSecuritySensitiveHTML(input) &&
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
    const name = (cookie.split("=", 1)[0] ?? "cookie").trim();
    if (!isSessionName(name.toLowerCase())) continue;
    const attributes = cookieAttributes(cookie);
    if (input.url.startsWith("http://") && !isLoopbackHost(input.host))
      output.push(
        baseCandidate(
          input,
          "header.cleartext_session_cookie",
          `Session cookie issued over cleartext HTTP: ${name}`,
          "Authentication / Transport",
          "High",
          "Firm",
          "WSTG-ATHN-01",
          `${name}=[REDACTED] delivered over HTTP`,
          "Move the endpoint to HTTPS before issuing session state, set Secure, and rotate sessions exposed over an untrusted network path.",
        ),
      );
    if (input.url.startsWith("https://") && !attributes.has("secure"))
      output.push(cookieCandidate(input, name, "secure", "Secure"));
    if (!attributes.has("httponly"))
      output.push(cookieCandidate(input, name, "httponly", "HttpOnly"));
    if (!attributes.has("samesite"))
      output.push(cookieCandidate(input, name, "samesite", "SameSite"));
  }
}

function analyzeAuthentication(
  input: AnalyzerInput,
  output: DetectedCandidate[],
): void {
  if (!isSuccessfulResponse(input)) return;
  const token = bearerToken(input);
  if (token === undefined) return;
  const jwt = parseJWT(token);
  if (jwt === undefined) return;
  const unsigned = jwt.algorithm?.toLowerCase() === "none";
  if (unsigned)
    output.push(
      baseCandidate(
        input,
        "auth.jwt_none",
        "Successful exchange used an unsigned JWT",
        "Authentication",
        "High",
        "Firm",
        "WSTG-ATHN-04",
        "Authorization bearer JWT declares alg=none; token value redacted",
        "Confirm the endpoint actually relied on this token by comparing an invalid signature and an unauthenticated request. Pin an allow-list of signed algorithms and reject none.",
      ),
    );
  if (!unsigned && jwt.subject !== undefined && jwt.expiresAt === undefined)
    output.push(
      baseCandidate(
        input,
        "auth.jwt_no_expiry",
        "JWT with a subject has no expiration claim",
        "Authentication",
        "Low",
        "Tentative",
        "WSTG-SESS-07",
        `JWT metadata: alg=${jwt.algorithm ?? "unspecified"}, sub present, exp absent`,
        "Determine whether this is an access token or an intentionally long-lived service token. Apply an expiry and revocation strategy appropriate to the token type.",
      ),
    );
  if (
    !unsigned &&
    jwt.issuedAt !== undefined &&
    jwt.expiresAt !== undefined &&
    jwt.expiresAt > jwt.issuedAt &&
    jwt.expiresAt - jwt.issuedAt > 7 * 24 * 60 * 60
  ) {
    const days = (jwt.expiresAt - jwt.issuedAt) / (24 * 60 * 60);
    output.push(
      baseCandidate(
        input,
        "auth.jwt_long_lifetime",
        "JWT lifetime exceeds seven days",
        "Authentication",
        "Information",
        "Tentative",
        "WSTG-SESS-07",
        `JWT metadata indicates a ${days.toFixed(1)} day lifetime; token value redacted`,
        "Classify the token (interactive access, refresh, or service token) before reporting. Shorten interactive access-token lifetime and use revocable refresh tokens where appropriate.",
      ),
    );
  }
}

function analyzeApiSignals(
  input: AnalyzerInput,
  output: DetectedCandidate[],
  assets: DetectedAsset[],
): void {
  const path = input.path.toLowerCase();
  if (input.responseBytes > 5 * 1024 * 1024)
    output.push(
      baseCandidate(
        input,
        "api.large_response",
        "Very large API response observed",
        "Resource consumption",
        "Low",
        "Tentative",
        "WSTG-APIT-03",
        `Response size: ${formatBytes(input.responseBytes)}`,
        "Confirm that this is not an intentional bulk export, then apply pagination, response-size caps, or streaming as appropriate.",
      ),
    );
  if (
    isSuccessfulResponse(input) &&
    isHeavyPath(path) &&
    !hasRateLimitSignal(input.responseHeaders) &&
    (input.responseBytes >= 1024 * 1024 || requestedLimit(input) >= 1_000)
  )
    output.push(
      baseCandidate(
        input,
        "api.resource_intensive_no_limit",
        "Resource-intensive API response lacks visible rate-limit signals",
        "Resource consumption",
        "Information",
        "Tentative",
        "WSTG-BUSL-05",
        `${input.method} ${path}; ${formatBytes(input.responseBytes)} response`,
        "Validate rate limiting at the CDN, gateway, and application layers. This rule requires a heavy route plus a large/requested result, but header absence still does not prove limits are missing.",
      ),
    );

  const responseJSON = input.responseContentType.toLowerCase().includes("json")
    ? parseJSON(input.responseBody)
    : undefined;
  if (isSuccessfulResponse(input) && Array.isArray(responseJSON)) {
    if (responseJSON.length > 100 && !looksPaginated(input))
      output.push(
        baseCandidate(
          input,
          "api.unbounded_array",
          "Large unpaginated JSON array observed",
          "Excessive data exposure",
          "Low",
          "Firm",
          "WSTG-APIT-03",
          `${responseJSON.length} top-level items; no common pagination signal observed`,
          "Check for a non-standard cursor or documented bulk-export contract. Otherwise add server-side pagination and a maximum page size.",
        ),
      );
    const fieldNames = topLevelArrayFields(responseJSON, 10);
    if (fieldNames.size > 20)
      output.push(
        baseCandidate(
          input,
          "api.excessive_fields",
          "Broad object projection in API array response",
          "Excessive data exposure",
          "Information",
          "Tentative",
          "WSTG-APIT-03",
          `${fieldNames.size} distinct top-level fields across sampled items`,
          "Compare the returned fields with what the client actually needs. Prefer explicit DTOs or field allow-lists; field count alone is not proof of sensitive exposure.",
        ),
      );
  }

  if (isOpenApiDocument(responseJSON)) {
    const url = redactURL(input.url);
    assets.push({ url, sourceUrl: url, kind: "OpenAPI definition" });
    output.push(
      baseCandidate(
        input,
        "api.definition_exposed",
        "OpenAPI definition observed",
        "API inventory",
        "Information",
        "Firm",
        "WSTG-APIT-01",
        "Response contains an OpenAPI/Swagger version and a paths object",
        "Add the documented operations to the inventory and compare them with observed traffic. Confirm whether production exposure is intentional and appropriately access-controlled.",
      ),
    );
  }
  if (
    /"__schema"\s*:/.test(input.responseBody) &&
    /"queryType"\s*:/.test(input.responseBody)
  )
    output.push(
      baseCandidate(
        input,
        "api.graphql_introspection",
        "GraphQL introspection response observed",
        "GraphQL",
        "Information",
        "Firm",
        "WSTG-APIT-99",
        "Response contains __schema and queryType introspection data",
        "Inventory the disclosed schema and verify field/resolver authorization. Disable production introspection only when it is not required and doing so fits the deployment model.",
      ),
    );
  const requestJSON = input.requestContentType.toLowerCase().includes("json")
    ? parseJSON(input.requestBody)
    : undefined;
  if (/\/graphql\/?$/i.test(path) && Array.isArray(requestJSON))
    output.push(
      baseCandidate(
        input,
        "api.graphql_batch",
        "GraphQL batch request observed",
        "Resource consumption",
        "Information",
        "Tentative",
        "WSTG-APIT-99",
        `Batch contains ${requestJSON.length} operations`,
        "Verify maximum batch size, query cost/depth controls, and per-operation authorization. A batch request is a capability signal, not a vulnerability by itself.",
      ),
    );
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
      if (!shouldReportSecret(input, rule, found, match.index ?? 0)) continue;
      const candidate = baseCandidate(
        input,
        rule.id,
        rule.title,
        "Secret / Information leak",
        rule.severity,
        rule.confidence,
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
    if (
      entropy < 3.5 ||
      isLikelyPlaceholder(token) ||
      isLikelyDocumentation(input)
    )
      continue;
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
  let passwordHashCount = 0;
  for (const match of body.matchAll(PASSWORD_HASH)) {
    if (passwordHashCount++ >= 5) break;
    const found = match[0];
    output.push(
      baseCandidate(
        input,
        "response.password_hash",
        "Password hash disclosed in response",
        "Excessive data exposure",
        "High",
        "Firm",
        "WSTG-APIT-03",
        `${mask(found)} at response offset ${match.index}`,
        "Confirm the value is a real credential hash, remove it from the response DTO, and assess whether credential resets are required.",
      ),
    );
  }
  let cardCount = 0;
  for (const match of body.matchAll(CARD_VALUE)) {
    if (cardCount++ >= 5) break;
    const candidateNumber = (match[1] ?? "").replace(/[^0-9]/g, "");
    if (!isPaymentCardNumber(candidateNumber)) continue;
    output.push(
      baseCandidate(
        input,
        "response.payment_card",
        "Potential payment card number disclosed in response",
        "Excessive data exposure",
        "High",
        "Firm",
        "WSTG-APIT-03",
        `${mask(candidateNumber)} at response offset ${match.index}`,
        "Confirm the field contains a full PAN rather than test or synthetic data, then return only a token or masked last four digits and follow the applicable data-handling requirements.",
      ),
    );
  }
  const sqlError =
    input.statusCode >= 400 && !isLikelyDocumentation(input)
      ? SQL_ERROR.exec(body)
      : null;
  const trace = STACK_TRACE.exec(body);
  const verbose =
    trace === null && sqlError === null ? VERBOSE_ERROR.exec(body) : null;
  if (sqlError !== null)
    output.push(
      baseCandidate(
        input,
        "response.sql_error",
        "Database error details disclosed",
        "Error handling",
        "Medium",
        "Firm",
        "WSTG-ERRH-01",
        context(body, sqlError.index, sqlError[0].length),
        "Reproduce with a benign malformed value. Treat this as an information leak unless a controlled input change introduces a new database error compared with the baseline.",
      ),
    );
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
  const internal = isLikelyDocumentation(input)
    ? undefined
    : findPrivateAddress(body);
  if (internal !== undefined)
    output.push(
      baseCandidate(
        input,
        "response.internal_address",
        "Internal network address disclosed",
        "Information gathering",
        "Information",
        "Firm",
        "WSTG-INFO-05",
        maskIPAddress(internal),
        "Confirm it belongs to private infrastructure and assess whether it expands attack-surface knowledge.",
      ),
    );
  if (!isJavaScript(input)) return;
  let count = 0;
  for (const match of body.matchAll(SOURCE_MAP)) {
    if (count++ >= 20) break;
    const value = match[1] ?? "";
    assets.push({
      url: redactURL(resolveURL(input.url, value)),
      sourceUrl: redactURL(input.url),
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
    assets.push({
      url: redactURL(match[0]),
      sourceUrl: redactURL(input.url),
      kind: "Absolute URL",
    });
  }
  count = 0;
  for (const match of body.matchAll(RELATIVE_ENDPOINT)) {
    if (count++ >= 200) break;
    assets.push({
      url: redactURL(resolveURL(input.url, match[1] ?? "")),
      sourceUrl: redactURL(input.url),
      kind: "JavaScript endpoint",
    });
  }
  if (DOM_SINK.test(body) && DOM_SOURCE.test(body))
    output.push(
      baseCandidate(
        input,
        "js.dom_sink",
        "Potential DOM source-to-sink flow",
        "Client-side injection",
        "Low",
        "Tentative",
        "WSTG-CLNT-01",
        "JavaScript contains both a browser-controlled source and an executable/HTML sink",
        "Trace the exact data flow from the source to the sink and verify context-appropriate encoding. Co-occurrence narrows review but does not prove reachability.",
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
    id === "samesite" ? "Tentative" : "Firm",
    "WSTG-SESS-02",
    `${name}=[REDACTED]`,
    id === "samesite"
      ? "Review the cookie's cross-site use and set an explicit SameSite policy. Modern default behavior reduces risk, so validate application context before reporting."
      : `Review cross-site and script access requirements, then add an appropriate ${attribute} attribute.`,
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

function addDuplicateParameterCandidates(
  input: AnalyzerInput,
  output: DetectedCandidate[],
): void {
  const groups = new Map<string, AnalyzerParameter[]>();
  for (const parameter of input.parameters) {
    if (parameter.location !== "QUERY" && parameter.location !== "FORM")
      continue;
    const name = parameter.name.trim().toLowerCase();
    if (name === "") continue;
    const key = `${parameter.location}\0${name}`;
    const values = groups.get(key) ?? [];
    values.push(parameter);
    groups.set(key, values);
  }
  for (const values of groups.values()) {
    if (values.length < 2) continue;
    const distinct = new Set(values.map((value) => value.value));
    if (distinct.size < 2) continue;
    const parameter = values[0];
    if (parameter === undefined) continue;
    output.push(
      parameterCandidate(
        input,
        parameter,
        "param.parameter_pollution",
        "Duplicate parameter with conflicting values observed",
        "HTTP parameter pollution",
        "Medium",
        "Tentative",
        "WSTG-INPV-04",
        "The captured query or form body contains the same name with different values. Different application layers may select different occurrences.",
        "Compare first-value, last-value, duplicate, and reordered variants. Confirm a security-relevant parser disagreement rather than reporting the duplicate itself.",
        "WSTGFLOW_HPP",
      ),
    );
  }
}

function looksIdentifier(value: string): boolean {
  const candidate = value.trim();
  if (/^[1-9]\d{0,18}$/.test(candidate)) return true;
  if (/^[a-f0-9]{24}$/i.test(candidate)) return true;
  if (
    /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(
      candidate,
    )
  )
    return true;
  return (
    candidate.length >= 8 &&
    candidate.length <= 64 &&
    /^[A-Za-z0-9_-]+$/.test(candidate) &&
    /[A-Za-z]/.test(candidate) &&
    /\d/.test(candidate)
  );
}

function objectIdentifierFromPath(path: string): string | undefined {
  const segments = path
    .split("/")
    .map((value) => safeDecode(value).toLowerCase())
    .filter((value) => value !== "");
  const resources = new Set([
    "user",
    "users",
    "account",
    "accounts",
    "order",
    "orders",
    "invoice",
    "invoices",
    "tenant",
    "tenants",
    "organization",
    "organizations",
    "orgs",
    "document",
    "documents",
    "record",
    "records",
    "customer",
    "customers",
    "project",
    "projects",
  ]);
  for (let index = 0; index < segments.length; index += 1) {
    const value = segments[index] ?? "";
    if (!looksIdentifier(value)) continue;
    const previous = segments[index - 1] ?? "";
    const apiContext =
      segments.includes("api") || segments.some(isVersionSegment);
    if (resources.has(previous) || apiContext) return value;
  }
  return undefined;
}

function isVersionSegment(value: string): boolean {
  return /^v\d+$/.test(value);
}

function isURLParameter(name: string): boolean {
  return (
    URL_PARAMETER_NAMES.has(name) ||
    name.endsWith("_url") ||
    name.endsWith("_uri")
  );
}

function looksURLValue(value: string): boolean {
  const candidate = safeDecode(value).trim();
  if (/^(?:https?|file|ftp|gopher):\/\//i.test(candidate)) return true;
  if (candidate.startsWith("//")) return true;
  return /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:\/|$)/i.test(candidate);
}

function looksPathValue(value: string): boolean {
  const candidate = safeDecode(value).trim();
  if (candidate === "" || /\s/.test(candidate)) return false;
  return (
    /(?:^|[./\\])\.\.?[/\\]/.test(candidate) ||
    candidate.includes("/") ||
    candidate.includes("\\") ||
    /(?:^|[/\\])[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,8}$/.test(candidate) ||
    /^[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,8}$/.test(candidate)
  );
}

function isCommandParameter(
  input: AnalyzerInput,
  name: string,
  value: string,
): boolean {
  if (COMMAND_PARAMETER_NAMES.has(name)) return value.trim() !== "";
  if (!["ping", "host", "hostname"].includes(name)) return false;
  if (
    !hasPathSegment(
      input.path,
      "diagnostic",
      "diagnostics",
      "network",
      "dns",
      "lookup",
      "resolve",
      "ping",
      "traceroute",
    )
  )
    return false;
  return /^(?:[a-z0-9-]+\.)*[a-z0-9-]+(?::\d+)?$/i.test(value.trim());
}

function reflectedInHTML(input: AnalyzerInput, value: string): boolean {
  if (!input.responseContentType.toLowerCase().includes("text/html"))
    return false;
  const candidate = safeDecode(value).trim();
  return (
    candidate.length >= 3 &&
    candidate.length <= 500 &&
    input.responseBody.includes(candidate)
  );
}

function isModifyingMethod(method: string): boolean {
  return ["POST", "PUT", "PATCH"].includes(method.toUpperCase());
}

function isSuccessfulResponse(input: AnalyzerInput): boolean {
  return (
    input.statusCode >= 200 &&
    input.statusCode < 300 &&
    !REJECTION.test(input.responseBody)
  );
}

function pathSegments(path: string): string[] {
  return path
    .split(/[/?#]/)
    .map((value) => safeDecode(value).toLowerCase())
    .filter((value) => value !== "");
}

function hasPathSegment(path: string, ...needles: string[]): boolean {
  const wanted = new Set(needles);
  return pathSegments(path).some(
    (segment) =>
      wanted.has(segment) ||
      [...wanted].some(
        (needle) =>
          segment.startsWith(`${needle}-`) || segment.endsWith(`-${needle}`),
      ),
  );
}

function looksDeprecatedPath(path: string): boolean {
  return pathSegments(path).some(
    (segment) =>
      segment === "v0" ||
      ["legacy", "deprecated", "old"].includes(segment) ||
      segment.endsWith("-old") ||
      segment.endsWith("-deprecated"),
  );
}

function isSensitiveBusinessPath(path: string): boolean {
  return hasPathSegment(
    path,
    "checkout",
    "payment",
    "payments",
    "purchase",
    "purchases",
    "buy",
    "transfer",
    "transfers",
    "withdraw",
    "withdrawal",
    "deposit",
    "register",
    "signup",
    "vote",
    "ballot",
  );
}

function isWebhookPath(path: string): boolean {
  return hasPathSegment(
    path,
    "webhook",
    "webhooks",
    "web-hook",
    "inbound-webhook",
    "hook-receiver",
  );
}

function hasAntiAutomation(input: AnalyzerInput): boolean {
  if (hasRateLimitSignal(input.responseHeaders)) return true;
  for (const name of ANTI_AUTOMATION_HEADERS)
    if (header(input.responseHeaders, name) !== "") return true;
  const lower = input.responseBody.toLowerCase();
  return ANTI_AUTOMATION_MARKERS.some((marker) => lower.includes(marker));
}

function isHeavyPath(path: string): boolean {
  return hasPathSegment(
    path,
    "search",
    "export",
    "report",
    "download",
    "bulk",
    "batch",
    "query",
  );
}

function hasRateLimitSignal(values: Record<string, string[]>): boolean {
  return Object.keys(values).some((name) => {
    const lower = name.toLowerCase();
    return RATE_LIMIT_PREFIXES.some((prefix) => lower.startsWith(prefix));
  });
}

function requestedLimit(input: AnalyzerInput): number {
  let maximum = 0;
  for (const parameter of input.parameters) {
    if (
      !["limit", "size", "page_size", "pagesize", "per_page"].includes(
        parameter.name.toLowerCase(),
      )
    )
      continue;
    const value = Number(parameter.value);
    if (Number.isFinite(value)) maximum = Math.max(maximum, value);
  }
  return maximum;
}

function looksPaginated(input: AnalyzerInput): boolean {
  const paginationHeaders = [
    "link",
    "x-total",
    "x-page",
    "x-per-page",
    "x-next",
    "x-pagination",
  ];
  if (
    Object.keys(input.responseHeaders).some((name) =>
      paginationHeaders.some((prefix) => name.toLowerCase().startsWith(prefix)),
    )
  )
    return true;
  return input.parameters.some((parameter) =>
    [
      "page",
      "offset",
      "limit",
      "per_page",
      "page_size",
      "cursor",
      "after",
      "before",
    ].includes(parameter.name.toLowerCase()),
  );
}

function parseJSON(value: string): unknown {
  if (value.trim() === "") return undefined;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function topLevelArrayFields(values: unknown[], maximum: number): Set<string> {
  const output = new Set<string>();
  for (const value of values.slice(0, maximum))
    if (isRecord(value)) Object.keys(value).forEach((key) => output.add(key));
  return output;
}

function isOpenApiDocument(value: unknown): boolean {
  return (
    isRecord(value) &&
    isRecord(value.paths) &&
    (typeof value.openapi === "string" || typeof value.swagger === "string")
  );
}

function formatBytes(value: number): string {
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${value} bytes`;
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

function cookieAttributes(value: string): Set<string> {
  const output = new Set<string>();
  for (const part of value.split(";").slice(1)) {
    const name = (part.split("=", 1)[0] ?? "").trim().toLowerCase();
    if (name !== "") output.add(name);
  }
  return output;
}

function requestCarriesCredentials(input: AnalyzerInput): boolean {
  const authorization = header(input.headers, "authorization").trim();
  if (authorization !== "") return true;
  for (const name of [
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
  ])
    if (header(input.headers, name).trim() !== "") return true;
  for (const cookie of headers(input.headers, "cookie")) {
    for (const pair of cookie.split(";")) {
      const name = (pair.split("=", 1)[0] ?? "").trim().toLowerCase();
      if (isSessionName(name)) return true;
    }
  }
  return input.parameters.some(
    (parameter) =>
      ["password", "passwd", "pwd", "credentials"].includes(
        parameter.name.toLowerCase(),
      ) && parameter.value !== "",
  );
}

function isLoopbackHost(value: string): boolean {
  const host = value.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "::1" ||
    /^127(?:\.\d{1,3}){3}$/.test(host)
  );
}

function traceResponseEchoesRequest(input: AnalyzerInput): boolean {
  const startLine = input.requestRaw.split(/\r?\n/, 1)[0] ?? "";
  if (startLine !== "" && input.responseBody.includes(startLine)) return true;
  const lower = input.responseBody.toLowerCase();
  return (
    lower.includes(`trace ${input.path.toLowerCase()}`) &&
    lower.includes(input.host.toLowerCase())
  );
}

function isSecuritySensitiveHTML(input: AnalyzerInput): boolean {
  if (
    hasPathSegment(
      input.path,
      "login",
      "signin",
      "auth",
      "account",
      "settings",
      "admin",
      "checkout",
      "payment",
      "transfer",
    )
  )
    return true;
  const body = input.responseBody.toLowerCase();
  return (
    /<form\b/.test(body) &&
    (/<input[^>]+type\s*=\s*["']?(?:password|submit)/.test(body) ||
      /<button\b/.test(body))
  );
}

function bearerToken(input: AnalyzerInput): string | undefined {
  const value = header(input.headers, "authorization");
  const match = /^Bearer\s+(\S+)$/i.exec(value.trim());
  return match?.[1];
}

type ParsedJWT = {
  algorithm?: string;
  expiresAt?: number;
  issuedAt?: number;
  subject?: string;
};

function parseJWT(value: string): ParsedJWT | undefined {
  if (value.length < 20 || value.length > 16_384) return undefined;
  const segments = value.split(".");
  if (segments.length !== 3 || segments[0] === "" || segments[1] === "")
    return undefined;
  try {
    const headerValue = JSON.parse(
      decodeBase64Url(segments[0] ?? ""),
    ) as unknown;
    const payloadValue = JSON.parse(
      decodeBase64Url(segments[1] ?? ""),
    ) as unknown;
    if (!isRecord(headerValue) || !isRecord(payloadValue)) return undefined;
    return {
      algorithm:
        typeof headerValue.alg === "string" ? headerValue.alg : undefined,
      expiresAt:
        typeof payloadValue.exp === "number" ? payloadValue.exp : undefined,
      issuedAt:
        typeof payloadValue.iat === "number" ? payloadValue.iat : undefined,
      subject:
        typeof payloadValue.sub === "string" ? payloadValue.sub : undefined,
    };
  } catch {
    return undefined;
  }
}

function decodeBase64Url(value: string): string {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (base64.length % 4)) % 4;
  const binary = atob(`${base64}${"=".repeat(padding)}`);
  return new TextDecoder().decode(
    Uint8Array.from(binary, (character) => character.charCodeAt(0)),
  );
}

function shouldReportSecret(
  input: AnalyzerInput,
  rule: SecretRule,
  found: string,
  index: number,
): boolean {
  if (isLikelyPlaceholder(found)) return false;
  const nearby = input.responseBody
    .slice(Math.max(0, index - 80), index + found.length + 80)
    .toLowerCase();
  if (
    isLikelyDocumentation(input) &&
    /(?:example|sample|dummy|mock|placeholder|replace[_ -]?me|your[_ -])/.test(
      nearby,
    )
  )
    return false;
  if (rule.id === "secret.jwt") {
    const contentType = input.responseContentType.toLowerCase();
    return (
      input.statusCode >= 400 ||
      isJavaScript(input) ||
      contentType.includes("text/html") ||
      contentType.includes("text/plain")
    );
  }
  return true;
}

function isLikelyPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  if (
    /(?:changeme|replace[_-]?me|placeholder|dummy|example|your[_-]?(?:key|token|secret))/.test(
      lower,
    )
  )
    return true;
  const compact = lower.replace(/[^a-z0-9]/g, "");
  if (/^(?:x|0|1|a){12,}$/.test(compact)) return true;
  const sequences = [
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "01234567890123456789",
    "12345678901234567890",
  ];
  return sequences.some(
    (sequence) => compact.length >= 12 && sequence.includes(compact),
  );
}

function isLikelyDocumentation(input: AnalyzerInput): boolean {
  return hasPathSegment(
    input.path,
    "docs",
    "documentation",
    "swagger",
    "api-docs",
    "openapi",
    "redoc",
  );
}

function isPaymentCardNumber(value: string): boolean {
  if (!/^\d{13,19}$/.test(value) || /^(\d)\1+$/.test(value)) return false;
  let sum = 0;
  let double = false;
  for (let index = value.length - 1; index >= 0; index -= 1) {
    let digit = Number(value[index]);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

function findPrivateAddress(value: string): string | undefined {
  for (const match of value.matchAll(INTERNAL_ADDRESS)) {
    const address = match[0];
    const octets = address.split(".").map(Number);
    if (
      octets.length === 4 &&
      octets.every(
        (octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255,
      )
    )
      return address;
  }
  return undefined;
}

function maskIPAddress(value: string): string {
  const parts = value.split(".");
  return parts.length === 4
    ? `${parts[0]}.${parts[1]}.[REDACTED].[REDACTED]`
    : "[REDACTED]";
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

function looksSessionToken(value: string): boolean {
  const candidate = value.trim();
  return (
    candidate.length >= 12 &&
    candidate.length <= 4_096 &&
    !isLikelyPlaceholder(candidate) &&
    shannonEntropy(candidate) >= 3
  );
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
  result = result.replace(PASSWORD_HASH, (found) => mask(found));
  result = result.replace(CARD_VALUE, (found, card: string) =>
    found.replace(card, mask(card.replace(/[^0-9]/g, ""))),
  );
  result = result.replace(INTERNAL_ADDRESS, (address) =>
    maskIPAddress(address),
  );
  return result.replace(GENERIC_SECRET, (found, token: string) =>
    found.replace(token, mask(token)),
  );
}

function redactURL(value: string): string {
  return value
    .replace(/^(https?:\/\/)[^/@\s]+@/i, "$1[REDACTED]@")
    .replace(
      /\/(?:\d{1,19}|[a-f0-9]{24}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})(?=\/|[?#]|$)/gi,
      "/[REDACTED]",
    )
    .replace(/([?&][^=&#]+)=([^&#]*)/g, "$1=[REDACTED]")
    .replace(
      /#(?=[^\s]*(?:token|secret|password|api[_-]?key|code)=).*/i,
      "#[REDACTED]",
    );
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
  confidence: Confidence = "Firm",
): SecretRule {
  return { id, title, severity, confidence, wstgId, pattern };
}
