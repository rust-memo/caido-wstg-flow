# Changelog

All notable changes to WSTG Flow are documented here.

## [1.1.0] - 2026-07-15

### Added

- Caido 0.57.1 SDK support and Node 22/pnpm 11 toolchain.
- Server-side pagination and filtering for candidates, assets, and findings.
- Versioned, idempotent database migrations and query indexes.
- Accessible confirmation dialog, keyboard-focus improvements, loading states, and complete HTML/JSON/CSV report generation in the backend.
- Automated coverage, dependency audit, build artifacts, release ZIP, and SHA-256 checksum workflows.
- Contributor, security, issue, and pull-request documentation.

### Changed

- Replaced full snapshot events with small batched change notifications.
- Saving Settings no longer deletes or rebuilds candidates; rebuilding is an explicit action.
- A/B verification now applies configured request and response size limits and refuses reuse of one exchange for both accounts.
- Finding publication records confirmation locally only after Caido accepts the deduplicated Finding.
- Split the frontend into focused views and shared controls.

### Fixed

- Idle Pause/Resume could leave the scanner in a false scanning state.
- Cancelled or previous-project workers could overwrite the current scanner state.
- Concurrent analysis could exceed the configured candidate cap, and a rebuild could overlap a final write from an older scan generation.
- Different A/B request targets could be reported as the same content.
- Stack-trace context could retain a neighboring secret already detected by another rule.
- Replay preparation could silently create an unchanged request after the source parameter disappeared.

## [1.0.0] - 2026-07-14

- Initial Caido-native WSTG Flow release.
