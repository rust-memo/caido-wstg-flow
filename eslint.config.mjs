import { defaultConfig } from "@caido/eslint-config";

/** @type {import('eslint').Linter.Config[]} */
export default [
  ...defaultConfig(),
  { ignores: ["packages/backend/src/catalog-data.ts"] },
  {
    files: ["packages/backend/src/**/*.ts"],
    // Caido's backend runs in its desktop runtime, not in the browser matrix
    // used by eslint-plugin-compat (which includes Opera Mini).
    rules: { "compat/compat": "off" },
  },
];
