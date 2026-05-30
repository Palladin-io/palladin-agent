import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
  },
  resolve: {
    // strip .js extensions so Vitest finds the TS source files
    extensionAlias: {
      '.js': ['.ts', '.js'],
    },
  },
})
