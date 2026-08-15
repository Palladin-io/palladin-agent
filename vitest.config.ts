import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30_000,
  },
  resolve: {
    alias: {
      '@palladin/agent/inject-contract': resolve(__dirname, 'src/inject-contract.ts'),
      '@palladin/agent/form-map': resolve(__dirname, 'src/form-map.ts'),
    },
    // strip .js extensions so Vitest finds the TS source files
    extensionAlias: {
      '.js': ['.ts', '.js'],
    },
  },
})
