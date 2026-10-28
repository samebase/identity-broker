import { defineConfig } from "vite-plus";

export default defineConfig({
  fmt: {
    ignorePatterns: ["**/_generated/**"],
    printWidth: 100,
    proseWrap: "always",
  },
  lint: {
    options: {
      typeAware: true,
    },
    plugins: ["eslint", "typescript"],
    env: {
      builtin: true,
      browser: true,
    },
    ignorePatterns: ["**/dist", "**/_generated"],
    jsPlugins: [
      {
        name: "@convex-dev",
        specifier: "@convex-dev/eslint-plugin",
      },
    ],
    rules: {
      "typescript/no-floating-promises": "error",
      // tsc never reports a deprecated API (TS6387 is an editor suggestion); the editor does, so
      // the type-aware lint must.
      "typescript/no-deprecated": "error",
    },
    overrides: [
      {
        files: ["packages/identity-broker/src/component/**/*.ts"],
        // The plugin's recommended rules. oxlint JS plugins get no type information, so
        // explicit-table-ids and no-filter-in-query use their syntax-only checks.
        rules: {
          "@convex-dev/no-old-registered-function-syntax": "error",
          "@convex-dev/require-args-validator": "error",
          "@convex-dev/explicit-table-ids": "error",
          "@convex-dev/no-filter-in-query": "warn",
          "@convex-dev/no-top-of-hour-crons": "warn",
          "@convex-dev/no-schema-import-cycle": "error",
          "@convex-dev/no-duplicate-indexes": "error",
          "@convex-dev/no-process-env": "error",
        },
      },
    ],
  },
  test: {
    // The edge-runtime environment clears `process`; Vitest fork teardown then crashes while
    // restoring `process.exit`. Threads avoid that teardown path.
    pool: "threads",
    environment: "edge-runtime",
    include: ["packages/*/src/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
  },
});
