import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@palladin/agent/form-map": fileURLToPath(
        new URL("../../src/form-map.ts", import.meta.url),
      ),
      "@palladin/agent/inject-contract": fileURLToPath(
        new URL("../../src/inject-contract.ts", import.meta.url),
      ),
      "openclaw/plugin-sdk/tool-plugin": fileURLToPath(
        new URL("./src/test-support/openclaw-tool-plugin.ts", import.meta.url),
      ),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
