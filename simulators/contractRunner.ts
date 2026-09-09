// Stop Point 8 — the contract-test runner.
//
// ONE runner drives the full matrix: every synthetic simulator × every
// failure mode (plus the well-behaved CONTROL scenario per simulator). Each
// cell is a complete scenario: inject the mode's configuration into the
// well-behaved scenario, assemble a fresh synthetic platform world, present
// the request plan `presentations` times under the SAME idempotency key (the
// mode's data owns the contract), open the webhook phase at the genuinely
// accepted outcome, and reduce everything the engines surfaced to ONE
// metadata-only ScenarioEvidence record + ONE Stop Point 10 certification
// row.
//
// Runner discipline:
//   * configuration-driven only — it reads ScenarioConfig records and never
//     branches on a specific partner, entitlement, or capability;
//   * injected deterministic clocks, synthetic sandbox secrets, no real
//     network (every transport is a scripted record);
//   * fail-closed — a scenario the runner cannot drive is a FAIL row, never
//     a silent skip, and any sensitive material detected on a surfaced
//     surface fails the scenario;
//   * metadata-only — evidence carries identifiers, contract codes, counts,
//     and booleans; the no-leak sweep re-checks every serialized surface
//     (views AND the evidence record itself) against the scenario's payload
//     and the synthetic secrets.

import {
  SYNTHETIC_SIMULATORS,
  SYNTHETIC_SIMULATOR_SECRETS,
  SYNTHETIC_WRONG_SIGNING_SECRET,
  makeScenarioClock,
  wellBehavedScenario,
} from './behaviors.ts';
import type {
  EvidenceSurface,
  ScenarioConfig,
  SimulatorIdentity,
} from './behaviors.ts';
import { CONTROL_MODE, FAILURE_MODES } from './failureModes.ts';
import type { FailureMode } from './failureModes.ts';
import { PartnerSimulator } from './partnerSimulator.ts';
import { SyntheticPlatform } from './syntheticPlatform.ts';
import {
  assertMetadataOnly,
  buildScenarioEvidence,
  certificationRowFor,
} from './evidence.ts';
import type { CertificationRow, ScenarioEvidence } from './evidence.ts';

// ---------------------------------------------------------------------------
// Public shapes
// ---------------------------------------------------------------------------

/** What the runner drives (defaults: every synthetic simulator × the whole catalog). */
export interface ContractRunnerOptions {
  /** Simulators under test (default: SYNTHETIC_SIMULATORS). */
  readonly simulators?: readonly SimulatorIdentity[];
  /** Failure modes under test (default: FAILURE_MODES). */
  readonly modes?: readonly FailureMode[];
  /** Run the well-behaved CONTROL scenario once per simulator (default: true). */
  readonly includeControl?: boolean;
}

/** The whole matrix run, reduced to counts + rows + evidence. */
export interface ContractRunSummary {
  readonly simulatorCount: number;
  readonly modeCount: number;
  readonly controlCount: number;
  readonly scenarioCount: number;
  readonly passedCount: number;
  readonly failedCount: number;
  /** True when every scenario in the matrix passed. */
  readonly allPassed: boolean;
  /** Certification rows in run order (the SP10 reporting shape). */
  readonly rows: readonly CertificationRow[];
  /** Evidence records in run order. */
  readonly evidence: readonly ScenarioEvidence[];
  /** Scenario identifiers that failed (identifiers only, never content). */
  readonly failedScenarioIds: readonly string[];
}

/** PASS/FAIL tallies per category (SP10 reporting convenience). */
export interface CategoryTally {
  readonly category: string;
  readonly total: number;
  readonly passed: number;
  readonly failed: number;
}

// ---------------------------------------------------------------------------
// Internal scenario shapes
// ---------------------------------------------------------------------------

/** One driven scenario's raw observations (codes + counts only). */
interface ScenarioObservations {
  /** Response code per presentation + second presentation, in call order. */
  readonly operationCodes: readonly string[];
  /** Receipt rejection reasons observed client-side, in order. */
  readonly receiptReasons: readonly string[];
  /** SDK retry plans computed per failed presentation at its attempt index. */
  readonly plans: readonly string[];
  /** Retry plan for the LAST failed presentation (the schedule-bound verdict). */
  readonly finalPlan: string | null;
  /** Transport invocations across every presentation. */
  readonly transportCalls: number;
  /** The request id of the first processed-OK outcome (the genuine accept). */
  readonly acceptedRequestId: string | null;
  /** True when any presentation (or second presentation) processed OK. */
  readonly anyProcessedOk: boolean;
}

const RUNNER_ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{3,63}$/;

/** Forbidden material for one scenario's no-leak sweep. */
function forbiddenMaterialFor(scenario: ScenarioConfig): readonly string[] {
  return [
    scenario.request.payload,
    SYNTHETIC_SIMULATOR_SECRETS.signing,
    SYNTHETIC_SIMULATOR_SECRETS.receipt,
    SYNTHETIC_SIMULATOR_SECRETS.webhook,
    SYNTHETIC_WRONG_SIGNING_SECRET,
  ];
}

/** Response code for one processed view (never payload content). */
function codeForProcessed(view: {
  ok: boolean;
  errorCode: string | null;
  receiptFailure: string | null;
}): string {
  if (view.ok) return 'OK';
  return view.errorCode ?? view.receiptFailure ?? 'UNKNOWN';
}

// ---------------------------------------------------------------------------
// Scenario execution — pure orchestration of the two engines
// ---------------------------------------------------------------------------

/**
 * Drive one scenario: fresh world + fresh simulator, present the request plan
 * `presentations` times (SAME plan, SAME idempotency key — the retry model's
 * clean-retry discipline), then open the webhook phase at the genuinely
 * accepted outcome.
 */
function driveScenario(scenario: ScenarioConfig): {
  observations: ScenarioObservations;
  phase: ReturnType<SyntheticPlatform['emitAndDeliver']>;
  platform: SyntheticPlatform;
} {
  const clock = makeScenarioClock();
  const platform = new SyntheticPlatform({ scenario, clock: clock.now });
  platform.assembleWorld();
  const simulator = new PartnerSimulator({ identity: scenario.identity, clock: clock.now });

  const presentations = Math.max(1, scenario.presentations ?? 1);
  const operationCodes: string[] = [];
  const receiptReasons: string[] = [];
  const plans: string[] = [];
  let finalPlan: string | null = null;
  let transportCalls = 0;
  let anyProcessedOk = false;
  let acceptedRequestId: string | null = null;
  let lastRequestId: string | null = null;

  for (let attempt = 1; attempt <= presentations; attempt += 1) {
    const outcome = simulator.execute(scenario.request, scenario.partnerFaults, platform);
    // The simulator's transport counter is cumulative per instance — the
    // latest observation IS the scenario total (never a sum).
    transportCalls = Math.max(transportCalls, outcome.transportCalls);
    lastRequestId = outcome.requestId;
    operationCodes.push(codeForProcessed(outcome.processed));
    if (outcome.processed.receiptFailure !== null) receiptReasons.push(outcome.processed.receiptFailure);
    if (outcome.processed.ok && acceptedRequestId === null) acceptedRequestId = outcome.requestId;
    if (outcome.processed.ok) anyProcessedOk = true;
    if (outcome.secondPresentation !== null) {
      operationCodes.push(codeForProcessed(outcome.secondPresentation));
      if (outcome.secondPresentation.receiptFailure !== null) {
        receiptReasons.push(outcome.secondPresentation.receiptFailure);
      }
      if (outcome.secondPresentation.ok) anyProcessedOk = true;
    }
    if (!outcome.processed.ok) {
      // The SDK retry plan for this failure at THIS attempt index — the
      // schedule-bound classification (EXHAUSTED at MAX_RETRY_ATTEMPTS).
      const failureCode = outcome.processed.errorCode ?? outcome.processed.receiptFailure;
      if (failureCode !== null) {
        const plan = simulator.planRetryFor(failureCode, attempt);
        plans.push(plan);
        finalPlan = plan;
      }
    }
  }

  // Open the webhook phase at the genuinely accepted outcome (the FIRST
  // processed-OK presentation). When nothing processed OK, the last request
  // stands — the platform's event gate fails closed on its own decision.
  const phase = platform.emitAndDeliver(acceptedRequestId ?? lastRequestId);

  return {
    observations: {
      operationCodes,
      receiptReasons,
      plans,
      finalPlan,
      transportCalls,
      acceptedRequestId,
      anyProcessedOk,
    },
    phase,
    platform,
  };
}

/** Every code the scenario surfaced, across every evidence surface. */
function observedCodes(
  run: ReturnType<typeof driveScenario>,
): Set<string> {
  const observed = new Set<string>();
  const add = (code: string | null | undefined): void => {
    if (typeof code === 'string' && code.length > 0) observed.add(code);
  };

  for (const code of run.observations.operationCodes) add(code);
  for (const reason of run.observations.receiptReasons) add(reason);
  for (const plan of run.observations.plans) add(plan);
  add(run.observations.finalPlan);
  add(run.platform.decisionView?.code ?? null);
  add(run.phase.delivery.deliveryOutcome);
  add(run.phase.delivery.deliveredTwiceOutcome);
  for (const code of run.phase.delivery.receiverCodes) add(code);
  add(run.phase.receiver.code);
  add(run.phase.receiver.rePresentedCode);
  for (const outcome of run.phase.delivery.reconciliationOutcomes) add(outcome);
  add(run.platform.spanViews.status);
  add(run.platform.spanViews.reconciliationStatus);
  for (const event of run.phase.events) add(event.eventType);
  for (const state of run.platform.circuitStateViews) add(state);
  for (const reason of run.platform.auditViews.reasonCodes) add(reason);
  return observed;
}

/** Serialize every surfaced surface for the no-leak sweep (views only). */
function serializeViews(run: ReturnType<typeof driveScenario>): string {
  return JSON.stringify({
    decision: run.platform.decisionView,
    delivery: run.phase.delivery,
    receiver: run.phase.receiver,
    events: run.phase.events,
    circuitStates: run.platform.circuitStateViews,
    span: run.platform.spanViews,
    audit: run.platform.auditViews,
  });
}

/** The primary observation for a mode's declared surface (FAIL reason). */
function primaryObservationFor(
  surface: EvidenceSurface,
  run: ReturnType<typeof driveScenario>,
  controlCompleted: boolean,
): string | null {
  const o = run.observations;
  switch (surface) {
    case 'CONTROL':
      return controlCompleted ? CONTROL_MODE.expectedCode
        : (o.operationCodes[o.operationCodes.length - 1] ?? null);
    case 'PLATFORM_RESPONSE':
      return run.platform.decisionView?.code ?? null;
    case 'RECEIPT':
      return o.receiptReasons.length > 0 ? o.receiptReasons[o.receiptReasons.length - 1] : null;
    case 'DELIVERY':
      return run.phase.delivery.deliveryOutcome;
    case 'RECEIVER':
      return run.phase.receiver.code ?? run.phase.receiver.rePresentedCode
        ?? (run.phase.delivery.receiverCodes.length > 0
          ? run.phase.delivery.receiverCodes[run.phase.delivery.receiverCodes.length - 1]
          : null);
    case 'EMIT':
      return run.phase.events.length > 0
        ? run.phase.events[run.phase.events.length - 1].eventType
        : null;
    case 'PLAN':
      return o.finalPlan;
    case 'SPAN':
      return run.platform.spanViews.reconciliationStatus ?? run.platform.spanViews.status;
    case 'CIRCUIT':
      return o.operationCodes.find((c) => c.startsWith('CIRCUIT')) ?? null;
    default:
      return null;
  }
}

/** The CONTROL contract: the full SP7 chain completed, end to end. */
function controlChainCompleted(
  run: ReturnType<typeof driveScenario>,
): boolean {
  const delivery = run.phase.delivery;
  return run.observations.anyProcessedOk
    && run.observations.receiptReasons.length === 0
    && delivery.deliveryOutcome === 'DELIVERED'
    && run.phase.receiver.verified === true
    && run.platform.spanViews.status === 'SUCCESS'
    && run.platform.auditViews.reasonCodes.includes('OPERATION_COMPLETED');
}

/** Contract checks that held (short identifiers only). */
function checksFor(input: {
  isControl: boolean;
  corePassed: boolean;
  failClosed: boolean;
  recoveryObserved: boolean;
  controlCompleted: boolean;
  presentations: number;
  viewsLeakFree: boolean;
  evidenceLeakFree: boolean;
}): readonly string[] {
  const checks: string[] = [];
  if (input.corePassed) checks.push('expected-code-observed');
  if (input.corePassed && input.failClosed) checks.push('fail-closed-refusal');
  if (input.corePassed && !input.failClosed && input.recoveryObserved) checks.push('contract-recovery');
  if (input.isControl && input.controlCompleted) checks.push('full-chain-completed');
  if (input.presentations > 1) checks.push('same-key-retry-discipline');
  if (input.viewsLeakFree) checks.push('metadata-only-views');
  if (input.evidenceLeakFree) checks.push('metadata-only-evidence');
  return checks;
}

/** A recovery/positive outcome was observed (fail-open contract modes). */
function recoveryObservedIn(run: ReturnType<typeof driveScenario>): boolean {
  return run.observations.anyProcessedOk
    || run.phase.receiver.verified === true
    || run.phase.delivery.deliveryOutcome === 'DELIVERED'
    || run.phase.delivery.deliveredTwiceOutcome === 'DELIVERED_DUPLICATE'
    || run.platform.spanViews.status === 'SUCCESS'
    || run.platform.spanViews.reconciliationStatus === 'RESOLVED';
}

// ---------------------------------------------------------------------------
// Evidence assembly (fail-closed on any runner or leak failure)
// ---------------------------------------------------------------------------

interface ScenarioSpec {
  readonly scenarioId: string;
  readonly simulatorId: string;
  readonly modeId: string;
  readonly category: string;
  readonly surface: EvidenceSurface;
  readonly expectedCode: string;
  readonly failClosed: boolean;
  readonly isControl: boolean;
}

/** Build the failure evidence for a scenario the runner could not drive. */
function runnerFailureEvidence(spec: ScenarioSpec, error: unknown): ScenarioEvidence {
  // Metadata-only: surface a TYPED code when the error carries one, never
  // message content.
  const message = error instanceof Error ? error.message : '';
  const observed = RUNNER_ERROR_CODE_PATTERN.test(message) ? message : 'RUNNER_ERROR';
  return buildScenarioEvidence({
    scenarioId: spec.scenarioId,
    simulatorId: spec.simulatorId,
    modeId: spec.modeId,
    category: spec.category as ScenarioEvidence['category'],
    surface: spec.surface,
    expectedCode: spec.expectedCode,
    observedCode: observed,
    passed: false,
    failClosed: spec.failClosed,
    checks: ['runner-fail-closed'],
  });
}

/** Reduce one driven scenario to its evidence record (with the leak sweep). */
function evidenceForScenario(
  spec: ScenarioSpec,
  scenario: ScenarioConfig,
): ScenarioEvidence {
  let run: ReturnType<typeof driveScenario>;
  try {
    run = driveScenario(scenario);
  } catch (error) {
    return runnerFailureEvidence(spec, error);
  }

  const forbidden = forbiddenMaterialFor(scenario);
  const observed = observedCodes(run);
  const controlCompleted = spec.isControl ? controlChainCompleted(run) : false;

  // Core verdict: the mode's expected contract code was observed somewhere
  // on the run's surfaced surfaces (the CONTROL mode: the full chain).
  const corePassed = spec.isControl
    ? controlCompleted && observed.has(spec.expectedCode)
    : observed.has(spec.expectedCode);

  // Primary observation for the declared surface (the FAIL reason code).
  const primary = primaryObservationFor(spec.surface, run, controlCompleted);

  // No-leak sweep: every surfaced view surface AND the evidence record
  // itself must be metadata-only for the scenario to pass.
  let viewsLeakFree = true;
  try {
    assertMetadataOnly(serializeViews(run), forbidden, 'VIEWS');
  } catch {
    viewsLeakFree = false;
  }

  const baseEvidence = {
    scenarioId: spec.scenarioId,
    simulatorId: spec.simulatorId,
    modeId: spec.modeId,
    category: spec.category as ScenarioEvidence['category'],
    surface: spec.surface,
    expectedCode: spec.expectedCode,
    observedCode: primary ?? (observed.size > 0 ? [...observed][0] : null),
    passed: corePassed,
    failClosed: spec.failClosed,
    retryPlan: run.observations.finalPlan,
    receiptReason: run.observations.receiptReasons.length > 0
      ? run.observations.receiptReasons[run.observations.receiptReasons.length - 1]
      : null,
    attempts: run.phase.delivery.deliveryAttemptCount,
    transportCalls: run.observations.transportCalls,
    deadLettered: run.phase.delivery.deadLettered,
    circuitStates: run.platform.circuitStateViews,
    operationCodes: run.observations.operationCodes,
    eventsEmitted: run.phase.events.map((e) => e.eventType),
    spanStatus: run.platform.spanViews.status,
    reconciliationStatus: run.platform.spanViews.reconciliationStatus,
  };

  const evidence = buildScenarioEvidence(baseEvidence);
  let evidenceLeakFree = true;
  try {
    assertMetadataOnly(JSON.stringify(evidence), forbidden, 'EVIDENCE');
  } catch {
    evidenceLeakFree = false;
  }

  const passed = corePassed && viewsLeakFree && evidenceLeakFree;
  const checks = checksFor({
    isControl: spec.isControl,
    corePassed,
    failClosed: spec.failClosed,
    recoveryObserved: recoveryObservedIn(run),
    controlCompleted,
    presentations: Math.max(1, scenario.presentations ?? 1),
    viewsLeakFree,
    evidenceLeakFree,
  });

  // Rebuild once with the FINAL pass verdict + checks (the checks list is
  // part of the evidence contract; the record stays metadata-only).
  const finalEvidence = buildScenarioEvidence({
    ...baseEvidence,
    passed,
    checks,
  });
  return finalEvidence;
}

// ---------------------------------------------------------------------------
// Public runner API
// ---------------------------------------------------------------------------

/** Run the CONTROL (well-behaved) scenario for one simulator. */
export function runControlScenario(identity: SimulatorIdentity): ScenarioEvidence {
  const spec: ScenarioSpec = {
    scenarioId: `${identity.simulatorId}:control`,
    simulatorId: identity.simulatorId,
    modeId: CONTROL_MODE.modeId,
    category: CONTROL_MODE.category,
    surface: CONTROL_MODE.surface,
    expectedCode: CONTROL_MODE.expectedCode,
    failClosed: CONTROL_MODE.failClosed,
    isControl: true,
  };
  return evidenceForScenario(spec, wellBehavedScenario(identity));
}

/** Run one failure mode against one simulator. */
export function runFailureModeScenario(
  identity: SimulatorIdentity,
  mode: FailureMode,
): ScenarioEvidence {
  const spec: ScenarioSpec = {
    scenarioId: `${identity.simulatorId}:${mode.modeId}`,
    simulatorId: identity.simulatorId,
    modeId: mode.modeId,
    category: mode.category,
    surface: mode.surface,
    expectedCode: mode.expectedCode,
    failClosed: mode.failClosed,
    isControl: false,
  };
  // The injector itself is wrapped: ANY failure to produce a driveable
  // scenario fails closed as a FAIL row with a typed code — never a crash,
  // never a silent skip.
  let scenario: ScenarioConfig;
  try {
    scenario = mode.inject(wellBehavedScenario(identity));
  } catch (error) {
    return runnerFailureEvidence(spec, error);
  }
  return evidenceForScenario(spec, scenario);
}

/** Run the whole contract matrix: every simulator × every mode (+ control). */
export function runContractMatrix(options: ContractRunnerOptions = {}): ContractRunSummary {
  const simulators = options.simulators ?? SYNTHETIC_SIMULATORS;
  const modes = options.modes ?? FAILURE_MODES;
  const includeControl = options.includeControl ?? true;

  const evidence: ScenarioEvidence[] = [];
  const rows: CertificationRow[] = [];
  const failedScenarioIds: string[] = [];

  for (const identity of simulators) {
    if (includeControl) {
      const record = runControlScenario(identity);
      evidence.push(record);
      rows.push(certificationRowFor(record));
      if (!record.passed) failedScenarioIds.push(record.scenarioId);
    }
    for (const mode of modes) {
      const record = runFailureModeScenario(identity, mode);
      evidence.push(record);
      rows.push(certificationRowFor(record));
      if (!record.passed) failedScenarioIds.push(record.scenarioId);
    }
  }

  const scenarioCount = evidence.length;
  const failedCount = failedScenarioIds.length;
  return Object.freeze({
    simulatorCount: simulators.length,
    modeCount: modes.length,
    controlCount: includeControl ? simulators.length : 0,
    scenarioCount,
    passedCount: scenarioCount - failedCount,
    failedCount,
    allPassed: scenarioCount > 0 && failedCount === 0,
    rows: Object.freeze(rows),
    evidence: Object.freeze(evidence),
    failedScenarioIds: Object.freeze(failedScenarioIds),
  });
}

/** PASS/FAIL tallies per category (the SP10 certification summary). */
export function talliesByCategory(summary: ContractRunSummary): readonly CategoryTally[] {
  const order: string[] = [];
  const map = new Map<string, { total: number; passed: number; failed: number }>();
  for (const row of summary.rows) {
    let tally = map.get(row.category);
    if (!tally) {
      tally = { total: 0, passed: 0, failed: 0 };
      map.set(row.category, tally);
      order.push(row.category);
    }
    tally.total += 1;
    if (row.result === 'PASS') tally.passed += 1;
    else tally.failed += 1;
  }
  return Object.freeze(order.map((category) => {
    const tally = map.get(category)!;
    return Object.freeze({ category, ...tally });
  }));
}
