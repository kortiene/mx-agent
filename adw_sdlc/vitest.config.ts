import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    server: {
      deps: {
        // runner-codex-spawn.test.ts asserts the secret boundary on the env
        // the REAL SDK builds for its child, which requires the test's
        // child_process mock to apply INSIDE the SDK — possible only when the
        // package is inlined through vitest's module runner instead of being
        // externalized to native Node import.
        inline: ['@openai/codex-sdk'],
      },
    },
  },
});
