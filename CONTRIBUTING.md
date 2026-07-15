# Contributing

Contributions are welcome when they preserve WSTG Flow's passive-first and explicit-scope safety boundaries.

## Development

Use Node.js 22 and pnpm 11, then run:

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test:coverage
pnpm lint
pnpm knip
pnpm audit --audit-level high
pnpm build
```

The package is written to `dist/plugin_package.zip`. Use synthetic or explicitly authorized traffic for manual testing and never commit project databases, raw HTTP, credentials, tokens, or private target information.

## Pull requests

- Keep passive detectors deterministic, bounded, and free of network calls.
- Treat candidates as review leads rather than vulnerability verdicts.
- Require an explicit confirmation for Replay preparation, destructive operations, and Finding publication.
- Add positive and negative tests for detector or comparator changes.
- Document user-visible changes in `CHANGELOG.md` and update compatibility requirements when SDK versions change.
