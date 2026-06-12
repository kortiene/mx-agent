import type { RunnerId } from './invoker.js';

/**
 * Base control-plane error (the TS analogue of `adw.common.AdwError`).
 * Thrown for expected, user-facing failures; anything else is a bug and
 * propagates as-is.
 */
export class AdwError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AdwError';
  }
}

/**
 * The selected runner's adapter or SDK could not be loaded. The four runner
 * SDKs are optionalDependencies reached only via dynamic import (PLAN.md D3),
 * so an absent one must surface as this typed error, never a raw
 * module-load crash.
 */
export class RunnerNotInstalledError extends AdwError {
  readonly runner: RunnerId;
  readonly sdkPackage: string;

  constructor(runner: RunnerId, sdkPackage: string, options?: ErrorOptions) {
    super(
      `runner '${runner}' is not installed: its adapter or SDK ('${sdkPackage}') failed to load. ` +
        `Install the optional dependency (pnpm add ${sdkPackage}) or select another runner.`,
      options,
    );
    this.name = 'RunnerNotInstalledError';
    this.runner = runner;
    this.sdkPackage = sdkPackage;
  }
}
