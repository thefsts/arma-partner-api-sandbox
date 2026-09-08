// Stop Point 7 — shared SDK: dependency health / readiness contract.
//
// Aggregated health is computed from named dependency probes. A REQUIRED
// dependency that is not AVAILABLE forces the aggregate to UNAVAILABLE
// (fail closed: callers must refuse new work). An OPTIONAL dependency that
// is not AVAILABLE only DEGRADES the aggregate — the surface may keep
// serving its core function without the optional capability.

export type DependencyStatus = 'AVAILABLE' | 'DEGRADED' | 'UNAVAILABLE';

export interface DependencyProbe {
  /** Stable identifier of the dependency (e.g. 'receipt-registry'). */
  readonly name: string;
  /** REQUIRED deps force aggregate UNAVAILABLE when down; OPTIONAL only degrade. */
  readonly criticality: 'REQUIRED' | 'OPTIONAL';
  /** Current probe result. */
  readonly status: DependencyStatus;
  /** Machine-readable reason code when status !== 'AVAILABLE'. */
  readonly reasonCode?: string;
}

export interface HealthReport {
  readonly status: 'AVAILABLE' | 'DEGRADED' | 'UNAVAILABLE';
  readonly checkedAt: number;
  readonly dependencies: readonly DependencyProbe[];
}

export interface HealthOptions {
  /** Injected clock (ms since epoch) — deterministic in tests. */
  readonly clock?: { now(): number };
}

export class DependencyHealthCheck {
  private readonly clock: { now(): number };

  constructor(options?: HealthOptions) {
    const now = options?.clock?.now;
    if (options && options.clock !== undefined && typeof now !== 'function') {
      throw new Error('HEALTH_CLOCK_INVALID');
    }
    this.clock = options?.clock ?? { now: () => Date.now() };
  }

  /**
   * Aggregate probe results into a single readiness verdict.
   * REQUIRED down => UNAVAILABLE. Any OPTIONAL down or any probe DEGRADED
   * (and no REQUIRED down) => DEGRADED. Otherwise AVAILABLE.
   */
  compute(dependencies: readonly DependencyProbe[]): HealthReport {
    if (!Array.isArray(dependencies)) throw new Error('HEALTH_INPUT_INVALID');
    for (const dep of dependencies) {
      if (dep === null || typeof dep !== 'object') throw new Error('HEALTH_INPUT_INVALID');
      if (typeof dep.name !== 'string' || !dep.name.trim()) throw new Error('HEALTH_INPUT_INVALID');
      if (dep.criticality !== 'REQUIRED' && dep.criticality !== 'OPTIONAL') {
        throw new Error('HEALTH_INPUT_INVALID');
      }
      if (dep.status !== 'AVAILABLE' && dep.status !== 'DEGRADED' && dep.status !== 'UNAVAILABLE') {
        throw new Error('HEALTH_INPUT_INVALID');
      }
      if (dep.status !== 'AVAILABLE' && (dep.reasonCode === undefined || typeof dep.reasonCode !== 'string' || !dep.reasonCode.trim())) {
        throw new Error('HEALTH_REASON_CODE_REQUIRED');
      }
    }
    let status: HealthReport['status'] = 'AVAILABLE';
    let anyDegraded = false;
    let anyRequiredDown = false;
    for (const dep of dependencies) {
      if (dep.criticality === 'REQUIRED' && dep.status === 'UNAVAILABLE') anyRequiredDown = true;
      if (dep.status !== 'AVAILABLE') anyDegraded = true;
    }
    if (anyRequiredDown) status = 'UNAVAILABLE';
    else if (anyDegraded) status = 'DEGRADED';
    return {
      status,
      checkedAt: this.clock.now(),
      dependencies: Object.freeze([...dependencies]),
    };
  }
}
