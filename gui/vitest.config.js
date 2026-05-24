import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['src/**/*.{test,spec}.{js,ts}'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{js,ts}'],
      exclude: ['src/__tests__/**', 'src/animations.js'],
      thresholds: {
        lines: 75,
        statements: 75,
        branches: 65,
        functions: 65,
      },
    },
  },
});
