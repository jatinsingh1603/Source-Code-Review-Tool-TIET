// The only ESLint configuration CodeKavach runs (E15-01).
//
// The scanned repository's own configuration is never loaded: the adapter passes --no-config-lookup
// and --no-inline-config, and hides eslint.config.* and the legacy .eslintrc* files from the view.
// This file enables the security rule set and nothing else.
//
// Licences: eslint-plugin-security is Apache-2.0. eslint-plugin-no-unsanitized is MPL-2.0, a
// file-level copyleft; it is used unmodified, installed from npm into the CodeKavach tools
// directory, and none of its files is copied into this repository.
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";

export default [
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.jsx"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    linterOptions: { noInlineConfig: true, reportUnusedDisableDirectives: "off" },
    plugins: { security, "no-unsanitized": noUnsanitized },
    rules: {
      ...security.configs.recommended.rules,
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",
    },
  },
];
