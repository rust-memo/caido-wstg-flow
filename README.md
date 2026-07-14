# WSTG Flow for Caido

WSTG Flow is a project-aware OWASP Web Security Testing Guide workbench for Caido. It combines an offline 113-test WSTG checklist with bounded passive analysis of Caido HTTP History, a candidate review queue, manual A/B evidence comparison, JavaScript asset inventory, Caido Finding publication, and redacted reports.

This is the Caido-native companion to the original Burp Suite `WSTG-Flow` extension. The Burp project remains independent and unchanged.

Passive analysis never sends requests. Payload actions only create an unsent Replay session. A/B verification only links two existing Caido exchanges that the tester has already sent and compares their saved responses.

Candidates are review leads, not vulnerability verdicts. Test only systems for which you have explicit authorization and manually validate every result before publishing a Finding.

## Features

- Bundles an offline snapshot of 113 WSTG tests, with categories, objectives, references, per-project status, notes, and candidate counts.
- Passively analyzes scoped HTTP History and newly intercepted responses with a bounded two-worker queue.
- Detects review candidates for access control, redirects, SSRF-like URL inputs, traversal, injection, dangerous rendering, privileged fields, GraphQL/admin routes, missing security headers, cookie attributes, secrets, verbose errors, internal addresses, and risky JavaScript patterns.
- Extracts JavaScript endpoints, source-map references, and script assets from traffic already present in Caido; it does not fetch assets itself.
- Deduplicates candidates, records occurrence counts, supports review states and WSTG remapping, and persists data separately for each Caido project.
- Opens the exact saved source request and response in read-only HTTP editors.
- Creates a modified Replay session for a selected payload after a confirmation prompt; it never sends the request.
- Links existing Account A and Account B Request IDs, then compares status, authentication barriers, content similarity, identity evidence, JSON fields, and selected header changes.
- Publishes a Caido Finding only after explicit confirmation and uses a stable deduplication key.
- Exports redacted HTML, JSON, and CSV reports. Request IDs, fingerprints, credentials, cookies, and common sensitive parameter values are excluded or masked.
- Supports pause, resume, cancel, bounded History rescan, ignored hosts, body-size limits, and scope-only mode.

## Requirements and build

- Node.js 20 or newer.
- pnpm 9.
- A current Caido release compatible with SDK `0.46.x`.

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm lint
pnpm knip
pnpm build
```

The loadable package is created at `dist/plugin_package.zip`.

## Install

1. Build the plugin or obtain `plugin_package.zip` from a trusted release.
2. Open Caido's plugin installation screen and load the ZIP package.
3. Add only authorized hosts to Caido Scope.
4. Open **WSTG Flow** from the Caido sidebar.

## Recommended workflow

1. Review **Settings** before scanning. Scope-only mode is enabled by default.
2. Proxy the application normally, or run a bounded History rescan. Analysis is local and passive.
3. Use **Dashboard** and **Candidates** to triage signals, read the source exchange, change the WSTG mapping, and write decision notes.
4. For a suggested payload, choose **Create Replay (do not send)**. Inspect and send it manually only when it is safe and authorized.
5. For authorization testing, send the Account A and Account B requests manually in Replay. In **A/B Verification**, attach their saved Request IDs to the candidate.
6. Review the comparison together with application semantics and real ownership. Similarity alone does not prove an authorization bypass.
7. Update the matching **Checklist** item and publish a Finding only after manual confirmation.
8. Export a redacted report from **Reports** when required.

## Safety and data boundaries

- No detector sends traffic, follows links, downloads JavaScript, brute-forces values, or performs enumeration.
- Replay preparation is scope-checked and creates a draft only.
- A/B comparison reads existing Caido messages; it does not impersonate users or send either request.
- History count, candidate count, request size, and response size are bounded in Settings.
- Binary and oversized bodies are skipped or clipped.
- Candidate URLs and evidence are masked before storage where applicable. Existing raw HTTP messages stay in the Caido project and are shown only through Caido's editors.
- Reports redact common credentials and secret parameter patterns and omit internal candidate fingerprints and Request IDs.
- Changing Settings rebuilds unconfirmed candidates. Confirmed findings and checklist progress are retained.

## Burp-to-Caido differences

The Caido release preserves the original checklist, passive discovery, candidate review, assets, evidence comparison, reports, payload suggestions, and confirmed-finding workflow using Caido-native History, Replay, SQLite, events, and Findings APIs. The first Caido release does not import Burp Scanner issues, execute probes automatically, use the Burp AI API, or import Burp-specific rule packs. These platform-specific features are intentionally not emulated.

## الاستخدام السريع بالعربية

1. ابنِ الإضافة ثم حمّل `dist/plugin_package.zip` من صفحة إضافات Caido.
2. أضف فقط الأهداف المصرّح باختبارها إلى **Caido Scope**.
3. التحليل السلبي يراجع الـ History والردود الجديدة محليًا ولا يرسل أي طلب.
4. راجع النتائج من **Candidates** واربطها باختبار WSTG المناسب.
5. زر الـ payload ينشئ Replay غير مُرسل؛ راجع الطلب وأرسله يدويًا فقط إذا كان آمنًا ومصرّحًا.
6. في اختبار A/B أرسل طلبي الحسابين بنفسك، ثم ضع Request ID لكل منهما ليقارن الردّين المحفوظين.
7. لا تعتبر التشابه أو أي Candidate ثغرة مؤكدة قبل التحقق من الملكية والصلاحيات والأثر يدويًا.
8. انشر Finding بعد التأكيد فقط، وصدّر تقرير HTML أو JSON أو CSV من تبويب **Reports**.

## WSTG snapshot

The bundled catalog was imported from the original Burp extension's offline checklist snapshot at commit `78e6b6733ee071eb160fdddbacc1bc97f83a13e3` (2026-06-30). OWASP WSTG content and links remain attributed to the OWASP Foundation and their applicable license.

## License

MIT. See [LICENSE](LICENSE).
