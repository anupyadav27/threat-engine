import { defineConfig, globalIgnores } from "eslint/config";
import nextPlugin from "@next/eslint-plugin-next";
import prettier from "eslint-config-prettier/flat";

export default defineConfig([
    {
        languageOptions: {
            parserOptions: {
                ecmaVersion: "latest",
                sourceType: "module",
                ecmaFeatures: {
                    jsx: true,
                },
            },
        },
        plugins: {
            next: nextPlugin,
        },
        rules: {},
    },

    nextPlugin.configs.recommended,

    prettier,

    globalIgnores([".next/**", "out/**", "build/**", "node_modules/**", "next-env.d.ts"]),
]);
