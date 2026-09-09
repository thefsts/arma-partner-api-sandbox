// Stop Point 10 — the integration certification reporter engine.
//
// Aggregates the evidence of EVERY test lane into the single owner-readable
// certification report: what is PASS, what is FAIL, and what was NOT TESTED
// — per requirement, per category, with safe reason codes and metadata-only
// evidence references.
//
// Reporter discipline (the proposal in docs/STOP-POINT-9-REPORT.md §10):
//   * NEVER PASS for an untested requirement — skip/todo/cancelled and any
//     evidence the reporter cannot fully interpret collapses to NOT-TESTED
//     with a typed reason code, never PASS, never a silent skip;
//   * one row shape everywhere — the SP8 `CertificationRow`
//     `{ testId, category, requirement, result, reasonCode }` plus the
//     metadata-only `sourceFile` evidence reference (the disambiguator for
//     legitimately repeated test names across files);
//   * deterministic — the same tree and the same lane evidence produce the
//     byte-identical report (rows canonically sorted; no timestamps, no
//     durations, no run-order dependence anywhere in the row set);
//   * fail-closed lane collection — a lane whose tests cannot run, crash,
//     emit malformed output, or disagree with its declared shape collapses
//     to NOT-TESTED rows with typed codes (never a crash, never a skip);
//   * metadata-only — rows carry identifiers, codes, counts, and the test
//     names; the leak sweep re-checks every serialized artifact against the
//     synthetic secrets and payload markers of the sandbox before anything
//     is written, and reason codes are structurally capped and constrained.
//
// The reporter RECORDS; it does not gate. The lanes already gate CI. A FAIL
// or NOT-TESTED row is printed to stdout and rendered in the report so it
// is visible to the owner, never buried.

// ---------------------------------------------------------------------------
// Row shape (the SP8 certification-row shape, verbatim, + evidence reference)
// ---------------------------------------------------------------------------

export type CertificationResult = 'PASS' | 'FAIL' | 'NOT-TESTED';

/** One certified requirement, in the SP8 shape + the evidence reference. */
export interface CertificationRow {
  /** Stable test identifier — source-file-qualified (`${sourceFile}::${testName}`). */
  readonly testId: string;
  /** Certification category (the owner-facing vocabulary). */
  readonly category: string;
  /** What the row certifies (the test name text, capped). */
  readonly requirement: string;
  readonly result: CertificationResult;
  /** Safe reason code (UPPER_SNAKE only — never message or payload content). */
  readonly reasonCode: string | null;
  /** Metadata-only evidence reference — the lane file that produced it. */
  readonly sourceFile: string;
}

// ---------------------------------------------------------------------------
// Structural limits (identifiers and codes only — by construction)
// ---------------------------------------------------------------------------

export const CERTIFICATION_LIMITS = Object.freeze({
  /** Max length of a row's `testId` and `requirement` text. */
  FIELD_MAX: 256,
  /** Max length of a safe reason code. */
  REASON_CODE_MAX: 128,
  /** Max length of a source-file evidence reference. */
  SOURCE_FILE_MAX: 200,
} as const);

/** Safe reason-code alphabet: UPPER_SNAKE only. */
const REASON_CODE_PATTERN = /^[A-Z][A-Z0-9_]*$/;

/** Result values the reporter accepts from lane evidence. */
const KNOWN_RESULTS = new Set<string>(['PASS', 'FAIL', 'NOT-TESTED']);

// ---------------------------------------------------------------------------
// Typed reporter reason codes (closed vocabulary — never message content)
// ---------------------------------------------------------------------------

/**
 * The reporter's own reason codes. These are CLOSED and structural — they
 * name the evidence condition, never message or payload content.
 */
export const REPORTER_REASON_CODES = Object.freeze({
  // Lane-collection collapse codes (a lane that could not be certified):
  LANE_UNCOLLECTABLE: 'LANE_UNCOLLECTABLE',
  LANE_EMPTY: 'LANE_EMPTY',
  LANE_MALFORMED_OUTPUT: 'LANE_MALFORMED_OUTPUT',
  LANE_COUNT_MISMATCH: 'LANE_COUNT_MISMATCH',
  LANE_MISSING: 'LANE_MISSING',
  LANE_UNDECLARED: 'LANE_UNDECLARED',
  LANE_OUTPUT_EMPTY: 'LANE_OUTPUT_EMPTY',
  LANE_COLLAPSE_PASS_WITHHELD: 'LANE_COLLAPSE_PASS_WITHHELD',
  // Row-level collapse codes:
  ROW_MALFORMED: 'ROW_MALFORMED',
  ROW_UNKNOWN_FIELD: 'ROW_UNKNOWN_FIELD',
  ROW_UNKNOWN_RESULT: 'ROW_UNKNOWN_RESULT',
  ROW_DUPLICATE_IDENTICAL: 'ROW_DUPLICATE_IDENTICAL',
  ROW_CONFLICTING_EVIDENCE: 'ROW_CONFLICTING_EVIDENCE',
  ROW_UNTESTED_DIRECTIVE: 'ROW_UNTESTED_DIRECTIVE',
  ROW_CANCELLED: 'ROW_CANCELLED',
  ROW_MISSING_REASON_CODE: 'ROW_MISSING_REASON_CODE',
  // Sweep code:
  SENSITIVE_MATERIAL_DETECTED: 'SENSITIVE_MATERIAL_DETECTED',
} as const);

export type ReporterReasonCode = keyof typeof REPORTER_REASON_CODES;

/**
 * Root-cause priority for a collapsed lane's reason code: the FIRST code in
 * this list that appears in the lane's problems is the collapse code. A lane
 * whose output could not be interpreted at all is `LANE_MALFORMED_OUTPUT`
 * regardless of any secondary count disagreement; a count disagreement on
 * otherwise well-formed output is `LANE_COUNT_MISMATCH`; a runner that died
 * outside its tests is `LANE_UNCOLLECTABLE`. Parse-level `TAP_*` codes stay
 * diagnostics in `problems` — they are never row reason codes.
 */
const LANE_COLLAPSE_PRIORITY: readonly string[] = Object.freeze([
  REPORTER_REASON_CODES.LANE_OUTPUT_EMPTY,
  REPORTER_REASON_CODES.LANE_MALFORMED_OUTPUT,
  REPORTER_REASON_CODES.LANE_COUNT_MISMATCH,
  REPORTER_REASON_CODES.LANE_UNCOLLECTABLE,
  REPORTER_REASON_CODES.LANE_EMPTY,
]);

// ---------------------------------------------------------------------------
// TAP parsing (node:test's stable TAP 13 output)
// ---------------------------------------------------------------------------

/** A raw test outcome parsed from one lane's TAP stream. */
export interface TapTestOutcome {
  /** Directive on the test line: none / skip / todo. */
  readonly directive: 'none' | 'skip' | 'todo';
  /** Raw ok/not-ok verdict from the TAP line (before directive semantics). */
  readonly ok: boolean;
  /** Unescaped test name, as the lane wrote it. */
  readonly name: string;
  /** failureType from the row's YAML block, when present (null otherwise). */
  readonly failureType: string | null;
  /** True when the row is a FILE-LEVEL failure row (a test file that could not load). */
  readonly fileLevel: boolean;
}

/** Lane-level TAP summary counters. */
export interface TapSummary {
  readonly tests: number;
  readonly pass: number;
  readonly fail: number;
  readonly cancelled: number;
  readonly skipped: number;
  readonly todo: number;
}

/** A parsed lane: outcomes, summary counters, and the structural verdict. */
export interface ParsedTap {
  readonly outcomes: readonly TapTestOutcome[];
  readonly summary: TapSummary;
  /** True when the TAP stream was structurally well-formed (plan + counters). */
  readonly wellFormed: boolean;
  /** Structural problems found (codes only). */
  readonly problems: readonly string[];
}

const TAP_ESCAPE_PATTERN = /\\([\\#])/g;

/** Unescape one TAP name (node escapes `#` and `\`). */
export function unescapeTapName(raw: string): string {
  return raw.replaceAll(TAP_ESCAPE_PATTERN, '$1');
}

const TAP_TEST_LINE = /^(not )?ok (\d+) - (.*)$/;
const TAP_DIRECTIVE = / # (SKIP|TODO)(?: .*)?$/;
const TAP_PLAN = /^1\.\.(\d+)(?: # (skip|todo))?$/;
const TAP_COUNT_LINE = /^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/;
const TAP_FAILURE_TYPE_LINE = /^\s{2}failureType: '?([^'\n]+)'?$/;
const TAP_EXIT_CODE_LINE = /^\s{2}exitCode: (\d+)$/;
const TAP_COUNT_KEYS = ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'] as const;
type TapCountKey = (typeof TAP_COUNT_KEYS)[number];

/**
 * Parse one lane's TAP stream (node:test --test-reporter=tap output).
 * Fail-closed: anything not a recognized test line / plan / counter /
 * diagnostic is a structural problem recorded as a code — never a throw,
 * never a silent skip. YAML detail blocks are scanned ONLY for the two
 * structural fields the reporter needs (failureType, exitCode); all other
 * detail (error messages, stacks, expected/actual) is discarded and can
 * never reach a row.
 */
export function parseTapStream(text: string): ParsedTap {
  if (typeof text !== 'string' || text.trim() === '') {
    return Object.freeze({
      outcomes: Object.freeze([]),
      summary: Object.freeze({ tests: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0 }),
      wellFormed: false,
      problems: Object.freeze(['LANE_OUTPUT_EMPTY']),
    });
  }

  const outcomes: TapTestOutcome[] = [];
  const problems: string[] = [];
  const counters: Partial<Record<TapCountKey, number>> = {};
  let plan = -1;
  let sawPlan = false;

  const lines = text.split('\n');
  for (const line of lines) {
    if (line === '' || line.startsWith('TAP version')) continue;
    if (line.startsWith('# Subtest:')) continue;

    const planMatch = TAP_PLAN.exec(line);
    if (planMatch) {
      if (sawPlan) problems.push('TAP_PLAN_DUPLICATE');
      plan = Number(planMatch[1]);
      sawPlan = true;
      continue;
    }

    const countMatch = TAP_COUNT_LINE.exec(line);
    if (countMatch) {
      const key = countMatch[1] as TapCountKey;
      counters[key] = Number(countMatch[2]);
      continue;
    }

    const testMatch = TAP_TEST_LINE.exec(line);
    if (testMatch) {
      const notOk = testMatch[1] !== undefined;
      let namePart = testMatch[3];
      const directiveMatch = TAP_DIRECTIVE.exec(namePart);
      let directive: 'none' | 'skip' | 'todo' = 'none';
      if (directiveMatch) {
        directive = directiveMatch[1] === 'SKIP' ? 'skip' : 'todo';
        namePart = namePart.slice(0, directiveMatch.index);
      }
      const name = unescapeTapName(namePart).trimEnd();
      if (name === '') problems.push('TAP_TEST_NAME_EMPTY');
      outcomes.push({ directive, ok: !notOk, name, failureType: null, fileLevel: false });
      continue;
    }

    // YAML detail blocks: structural fields only, everything else discarded.
    if (line.startsWith('  ---') || line.startsWith('  ...')) continue;
    if (line.startsWith('  ')) {
      if (outcomes.length > 0) {
        const failureTypeMatch = TAP_FAILURE_TYPE_LINE.exec(line);
        const exitCodeMatch = TAP_EXIT_CODE_LINE.exec(line);
        const last = outcomes[outcomes.length - 1];
        if (failureTypeMatch) {
          outcomes[outcomes.length - 1] = { ...last, failureType: failureTypeMatch[1] };
        } else if (exitCodeMatch) {
          outcomes[outcomes.length - 1] = { ...last, fileLevel: true };
        }
      }
      continue;
    }
    if (line.startsWith('#')) continue;

    problems.push('TAP_LINE_UNRECOGNIZED');
  }

  const summary = Object.freeze({
    tests: counters.tests ?? 0,
    pass: counters.pass ?? 0,
    fail: counters.fail ?? 0,
    cancelled: counters.cancelled ?? 0,
    skipped: counters.skipped ?? 0,
    todo: counters.todo ?? 0,
  });
  const parsedCount = outcomes.length;
  const countersComplete = counters.tests !== undefined;
  const countsConsistent =
    summary.tests === parsedCount &&
    summary.pass + summary.fail + summary.cancelled + summary.skipped + summary.todo === summary.tests;
  const planConsistent = !sawPlan ? false : plan === parsedCount;
  const wellFormed = countersComplete && countsConsistent && planConsistent;
  if (!countersComplete) problems.push('TAP_COUNTERS_MISSING');
  if (!countsConsistent) problems.push('TAP_COUNTERS_INCONSISTENT');
  if (!sawPlan) problems.push('TAP_PLAN_MISSING');

  return Object.freeze({
    outcomes: Object.freeze(outcomes),
    summary,
    wellFormed,
    problems: Object.freeze(problems),
  });
}

// ---------------------------------------------------------------------------
// Row validation (never PASS for anything not fully understood)
// ---------------------------------------------------------------------------

/** Row keys the reporter accepts (the SP8 shape + sourceFile). */
const KNOWN_ROW_KEYS = new Set<string>(['testId', 'category', 'requirement', 'result', 'reasonCode', 'sourceFile']);

/** A coerced row outcome: the row (or null when identity did not survive) + the problem code. */
export interface CoercedRow {
  readonly row: CertificationRow | null;
  readonly problem: string | null;
}

const cap = (value: string, max: number): string => (value.length > max ? value.slice(0, max) : value);

/** Build the degraded (NOT-TESTED) row preserving identity, with a typed code. */
function degradedRow(
  testId: string,
  category: string,
  requirement: string,
  reasonCode: string,
  sourceFile: string,
): CertificationRow {
  return Object.freeze({
    testId: cap(testId, CERTIFICATION_LIMITS.FIELD_MAX),
    category: cap(category, CERTIFICATION_LIMITS.FIELD_MAX),
    requirement: cap(requirement, CERTIFICATION_LIMITS.FIELD_MAX),
    result: 'NOT-TESTED' as const,
    reasonCode,
    sourceFile: cap(sourceFile, CERTIFICATION_LIMITS.SOURCE_FILE_MAX),
  });
}

/**
 * Coerce one raw candidate row (used when rows arrive as data, not TAP).
 * Fails closed: any unknown field, unknown result value, or non-safe reason
 * code degrades the row to NOT-TESTED with a typed code when the row's
 * identity survives, or drops it (with the problem recorded) when it does
 * not. NEVER PASS for anything not fully understood.
 */
export function coerceRow(input: unknown, sourceFile: string): CoercedRow {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { row: null, problem: 'ROW_MALFORMED' };
  }
  const record = input as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!KNOWN_ROW_KEYS.has(key)) return { row: null, problem: 'ROW_UNKNOWN_FIELD' };
  }
  const testId = typeof record.testId === 'string' ? record.testId.trim() : '';
  const category = typeof record.category === 'string' ? record.category.trim() : '';
  const requirement = typeof record.requirement === 'string' ? record.requirement.trim() : '';
  if (testId === '' || category === '' || requirement === '') {
    return { row: null, problem: 'ROW_MALFORMED' };
  }
  const file = cap(sourceFile, CERTIFICATION_LIMITS.SOURCE_FILE_MAX);

  const resultRaw = record.result;
  if (typeof resultRaw !== 'string' || !KNOWN_RESULTS.has(resultRaw)) {
    return {
      row: degradedRow(testId, category, requirement, REPORTER_REASON_CODES.ROW_UNKNOWN_RESULT, file),
      problem: 'ROW_UNKNOWN_RESULT',
    };
  }
  const result = resultRaw as CertificationResult;

  let reasonCode: string | null =
    record.reasonCode === null || record.reasonCode === undefined ? null : String(record.reasonCode);

  if (result === 'PASS' && reasonCode === null) {
    // A PASS without its expected code is not fully understood evidence.
    return {
      row: degradedRow(testId, category, requirement, REPORTER_REASON_CODES.ROW_MISSING_REASON_CODE, file),
      problem: 'ROW_MISSING_REASON_CODE',
    };
  }
  if (reasonCode !== null && !REASON_CODE_PATTERN.test(reasonCode)) {
    return {
      row: degradedRow(testId, category, requirement, REPORTER_REASON_CODES.ROW_MALFORMED, file),
      problem: 'ROW_MALFORMED',
    };
  }
  if (reasonCode !== null && reasonCode.length > CERTIFICATION_LIMITS.REASON_CODE_MAX) {
    return {
      row: degradedRow(testId, category, requirement, REPORTER_REASON_CODES.ROW_MALFORMED, file),
      problem: 'ROW_MALFORMED',
    };
  }
  if (reasonCode !== null) reasonCode = cap(reasonCode, CERTIFICATION_LIMITS.REASON_CODE_MAX);

  return {
    row: Object.freeze({
      testId: cap(testId, CERTIFICATION_LIMITS.FIELD_MAX),
      category: cap(category, CERTIFICATION_LIMITS.FIELD_MAX),
      requirement: cap(requirement, CERTIFICATION_LIMITS.FIELD_MAX),
      result,
      reasonCode,
      sourceFile: file,
    }),
    problem: null,
  };
}

// ---------------------------------------------------------------------------
// TAP outcome → row mapping (the per-lane adapter)
// ---------------------------------------------------------------------------

/** Lane category vocabularies (owner-facing, closed — SP8 + SP9 + lane ids). */
export const LANE_CATEGORIES = Object.freeze({
  LAW_SHIELD: 'LAW_SHIELD',
  PATCHES_CONTRACT: 'PATCHES_CONTRACT',
  PATCHES_ADAPTER: 'PATCHES_ADAPTER',
  AI_GOVERNANCE: 'AI_GOVERNANCE',
  SHARED: 'SHARED',
  SIMULATORS: 'SIMULATORS',
  SIMULATORS_MATRIX: 'SIMULATORS_MATRIX',
  OPENAPI_STRUCTURE: 'OPENAPI_STRUCTURE',
  OPENAPI_CROSSCHECK: 'OPENAPI_CROSSCHECK',
  OPENAPI_LIVE_CONFORMANCE: 'OPENAPI_LIVE_CONFORMANCE',
  CERTIFICATION: 'CERTIFICATION',
  // A test file found on disk that the committed manifest does not declare:
  UNDECLARED: 'UNDECLARED',
  // SP8 failure-mode categories carried by matrix rows verbatim:
  CONTROL: 'CONTROL',
  SIGNATURE: 'SIGNATURE',
  REPLAY: 'REPLAY',
  RECEIPT: 'RECEIPT',
  AUTHORIZATION: 'AUTHORIZATION',
  ENTITLEMENT: 'ENTITLEMENT',
  WEBHOOK: 'WEBHOOK',
  RETRY: 'RETRY',
  RECONCILIATION: 'RECONCILIATION',
  CIRCUIT_BREAKER: 'CIRCUIT_BREAKER',
  KILL_SWITCH: 'KILL_SWITCH',
} as const);

/**
 * Map one TAP outcome to its certification row. Fail-closed semantics:
 *   * skip/todo directive → NOT-TESTED (the requirement was not executed);
 *   * a cancelled row (timeout failureType) → NOT-TESTED TEST_CANCELLED;
 *   * a file-level failure row (a file that could not load) → NOT-TESTED
 *     LANE_MALFORMED_OUTPUT (the lane-level collapse carries the detail);
 *   * not ok → FAIL TEST_FAILED (visible, never buried);
 *   * ok (no directive) → PASS TEST_PASSED.
 */
export function rowForTapOutcome(outcome: TapTestOutcome, category: string, sourceFile: string): CertificationRow {
  const testId = cap(`${sourceFile}::${outcome.name}`, CERTIFICATION_LIMITS.FIELD_MAX);
  const requirement = cap(outcome.name, CERTIFICATION_LIMITS.FIELD_MAX);
  const file = cap(sourceFile, CERTIFICATION_LIMITS.SOURCE_FILE_MAX);

  if (outcome.directive === 'skip' || outcome.directive === 'todo') {
    return Object.freeze({
      testId,
      category,
      requirement,
      result: 'NOT-TESTED' as const,
      reasonCode: outcome.directive === 'skip' ? 'SKIP' : 'TODO',
      sourceFile: file,
    });
  }
  if (outcome.fileLevel) {
    return Object.freeze({
      testId,
      category,
      requirement,
      result: 'NOT-TESTED' as const,
      reasonCode: REPORTER_REASON_CODES.LANE_MALFORMED_OUTPUT,
      sourceFile: file,
    });
  }
  if (outcome.failureType === 'testTimeoutFailure') {
    return Object.freeze({
      testId,
      category,
      requirement,
      result: 'NOT-TESTED' as const,
      reasonCode: REPORTER_REASON_CODES.ROW_CANCELLED,
      sourceFile: file,
    });
  }
  if (!outcome.ok) {
    return Object.freeze({
      testId,
      category,
      requirement,
      result: 'FAIL' as const,
      reasonCode: 'TEST_FAILED',
      sourceFile: file,
    });
  }
  return Object.freeze({
    testId,
    category,
    requirement,
    result: 'PASS' as const,
    reasonCode: 'TEST_PASSED',
    sourceFile: file,
  });
}

// ---------------------------------------------------------------------------
// Lane collection (fail-closed collapse)
// ---------------------------------------------------------------------------

/** What a lane declares about itself (cross-checked at collection time). */
export interface LaneDeclaration {
  /** The lane's stable id (e.g. 'shared'). */
  readonly laneId: string;
  /** The lane's category (vocabulary above). */
  readonly category: string;
  /** TAP text from running the lane's tests. */
  readonly tap: string;
  /** The lane's declared test count (cross-checked against TAP). */
  readonly declaredTests: number;
  /** The source files the lane ran (metadata-only evidence references). */
  readonly sourceFiles: readonly string[];
  /** The lane runner's exit status (null when not run / unknown). */
  readonly runnerExit: number | null;
}

/** One lane's collection result. */
export interface LaneResult {
  readonly laneId: string;
  readonly rows: readonly CertificationRow[];
  /** Structural problems (codes only) — non-empty means collapse. */
  readonly problems: readonly string[];
  /** True when the lane collapsed (fail-closed). */
  readonly collapsed: boolean;
  /** The collapse reason code (null when not collapsed). */
  readonly collapseCode: string | null;
}

/**
 * Collect one TAP lane. Fail-closed: structural problems (malformed output,
 * count mismatch, empty output, uncollectable runner) collapse the lane —
 * every PASS the lane emitted is WITHHELD to NOT-TESTED with the typed
 * code (the reporter cannot certify a lane whose evidence is structurally
 * broken), while FAIL rows stay FAIL (visible, never buried) and skip/todo
 * rows stay NOT-TESTED. A lane with no outcomes at all collapses to ONE
 * lane-level NOT-TESTED row with the first problem code.
 */
export function collectLane(declaration: LaneDeclaration): LaneResult {
  const problems: string[] = [];
  const parsed = parseTapStream(declaration.tap);

  for (const problem of parsed.problems) problems.push(problem);
  // An explicit structural break: any parse-level TAP_* problem or a
  // not-well-formed stream means the lane's output could not be interpreted
  // — recorded as LANE_MALFORMED_OUTPUT so the root-cause priority can pick
  // it over any secondary disagreement.
  if (parsed.problems.some((code) => code.startsWith('TAP_')) || !parsed.wellFormed) {
    problems.push(REPORTER_REASON_CODES.LANE_MALFORMED_OUTPUT);
  }

  // Count cross-check: TAP's own `# tests N` vs the declared count.
  if (parsed.summary.tests !== declaration.declaredTests) problems.push('LANE_COUNT_MISMATCH');

  // A file-level failure row means a test file could not even load.
  if (parsed.outcomes.some((outcome) => outcome.fileLevel)) problems.push('LANE_MALFORMED_OUTPUT');

  // A runner that exited non-zero with no failing/cancelled test rows
  // failed OUTSIDE the tests (load error, crash) — uncollectable.
  if (declaration.runnerExit !== null && declaration.runnerExit !== 0) {
    const rowLevelFailures = parsed.summary.fail + parsed.summary.cancelled;
    if (rowLevelFailures === 0) problems.push('LANE_UNCOLLECTABLE');
  }

  if (problems.length === 0 && parsed.outcomes.length === 0) problems.push('LANE_EMPTY');

  if (problems.length > 0) {
    // The collapse code is the ROOT-CAUSE lane code by priority: parse-level
    // TAP_* codes stay in `problems` as diagnostics and are never surfaced
    // as row reason codes.
    const laneCollapseCode = LANE_COLLAPSE_PRIORITY.find((code) => problems.includes(code))
      ?? REPORTER_REASON_CODES.LANE_MALFORMED_OUTPUT;
    // COLLAPSE — fail-closed, metadata-only, never a crash.
    if (parsed.outcomes.length > 0) {
      const rows = parsed.outcomes.map((outcome) =>
        rowForTapOutcome(outcome, declaration.category, declaration.sourceFiles[0] ?? declaration.laneId));
      const collapsedRows = rows.map((row) =>
        row.result === 'PASS'
          ? Object.freeze({ ...row, result: 'NOT-TESTED' as const, reasonCode: 'LANE_COLLAPSE_PASS_WITHHELD' })
          : row);
      return Object.freeze({
        laneId: declaration.laneId,
        rows: Object.freeze(collapsedRows),
        problems: Object.freeze(problems),
        collapsed: true,
        collapseCode: laneCollapseCode,
      });
    }
    return Object.freeze({
      laneId: declaration.laneId,
      rows: Object.freeze([
        Object.freeze({
          testId: cap(`${declaration.laneId}:lane`, CERTIFICATION_LIMITS.FIELD_MAX),
          category: declaration.category,
          requirement: cap(`lane ${declaration.laneId} could not be certified`, CERTIFICATION_LIMITS.FIELD_MAX),
          result: 'NOT-TESTED' as const,
          reasonCode: laneCollapseCode,
          sourceFile: cap(declaration.sourceFiles[0] ?? declaration.laneId, CERTIFICATION_LIMITS.SOURCE_FILE_MAX),
        }),
      ]),
      problems: Object.freeze(problems),
      collapsed: true,
      collapseCode: laneCollapseCode,
    });
  }

  const rows = parsed.outcomes.map((outcome) =>
    rowForTapOutcome(outcome, declaration.category, declaration.sourceFiles[0] ?? declaration.laneId));
  return Object.freeze({
    laneId: declaration.laneId,
    rows: Object.freeze(rows),
    problems: Object.freeze([]),
    collapsed: false,
    collapseCode: null,
  });
}

/** Build a lane result from rows produced in-process (the SP8 matrix lane). */
export function laneFromRows(
  laneId: string,
  rows: readonly CertificationRow[],
): LaneResult {
  return Object.freeze({
    laneId,
    rows: Object.freeze(rows),
    problems: Object.freeze([]),
    collapsed: false,
    collapseCode: null,
  });
}

/** The collapsed variant of an in-process lane (fail-closed, one row). */
export function collapsedInProcessLane(laneId: string, category: string, reasonCode: string): LaneResult {
  return Object.freeze({
    laneId,
    rows: Object.freeze([
      Object.freeze({
        testId: cap(`${laneId}:lane`, CERTIFICATION_LIMITS.FIELD_MAX),
        category,
        requirement: cap(`lane ${laneId} could not be certified`, CERTIFICATION_LIMITS.FIELD_MAX),
        result: 'NOT-TESTED' as const,
        reasonCode,
        sourceFile: cap(laneId, CERTIFICATION_LIMITS.SOURCE_FILE_MAX),
      }),
    ]),
    problems: Object.freeze([reasonCode]),
    collapsed: true,
    collapseCode: reasonCode,
  });
}

// ---------------------------------------------------------------------------
// Duplicate / conflict resolution
// ---------------------------------------------------------------------------

/** A row plus the lane it belongs to (attribution for summaries). */
interface LaneEntry {
  readonly row: CertificationRow;
  readonly laneId: string;
}

/** Resolve duplicates: identical → NOT-TESTED; divergent (conflict) → FAIL. */
export function resolveDuplicates(rows: readonly CertificationRow[]): {
  readonly rows: readonly CertificationRow[];
  readonly duplicateCount: number;
  readonly conflictCount: number;
} {
  const entries: LaneEntry[] = rows.map((row) => ({ row, laneId: '' }));
  const resolved = resolveDuplicateEntries(entries);
  return { rows: resolved.rows, duplicateCount: resolved.duplicateCount, conflictCount: resolved.conflictCount };
}

/** Same resolution over attributed entries (used by assembleReport). */
export function resolveDuplicateEntries(entries: readonly LaneEntry[]): {
  readonly rows: readonly CertificationRow[];
  readonly laneIds: readonly string[];
  readonly duplicateCount: number;
  readonly conflictCount: number;
} {
  const byId = new Map<string, LaneEntry[]>();
  for (const entry of entries) {
    const list = byId.get(entry.row.testId) ?? [];
    list.push(entry);
    byId.set(entry.row.testId, list);
  }
  const rows: CertificationRow[] = [];
  const laneIds: string[] = [];
  let duplicateCount = 0;
  let conflictCount = 0;
  for (const list of byId.values()) {
    if (list.length === 1) {
      rows.push(list[0].row);
      laneIds.push(list[0].laneId);
      continue;
    }
    const first = list[0].row;
    const identical = list.every((entry) =>
      entry.row.requirement === first.requirement &&
      entry.row.result === first.result &&
      entry.row.reasonCode === first.reasonCode &&
      entry.row.sourceFile === first.sourceFile &&
      entry.row.category === first.category);
    if (identical) {
      duplicateCount += 1;
      rows.push(Object.freeze({
        testId: first.testId,
        category: first.category,
        requirement: first.requirement,
        result: 'NOT-TESTED' as const,
        reasonCode: REPORTER_REASON_CODES.ROW_DUPLICATE_IDENTICAL,
        sourceFile: first.sourceFile,
      }));
    } else {
      conflictCount += 1;
      rows.push(Object.freeze({
        testId: first.testId,
        category: first.category,
        requirement: first.requirement,
        result: 'FAIL' as const,
        reasonCode: REPORTER_REASON_CODES.ROW_CONFLICTING_EVIDENCE,
        sourceFile: first.sourceFile,
      }));
    }
    laneIds.push(list[0].laneId);
  }
  return { rows: Object.freeze(rows), laneIds: Object.freeze(laneIds), duplicateCount, conflictCount };
}

// ---------------------------------------------------------------------------
// Report assembly (deterministic)
// ---------------------------------------------------------------------------

/** Per-category PASS/FAIL/NOT-TESTED tallies. */
export interface CategoryTally {
  readonly category: string;
  readonly total: number;
  readonly pass: number;
  readonly fail: number;
  readonly notTested: number;
}

/** Per-lane row counts + collapse state. */
export interface LaneSummary {
  readonly laneId: string;
  readonly rowCount: number;
  readonly pass: number;
  readonly fail: number;
  readonly notTested: number;
  readonly collapsed: boolean;
  readonly collapseCode: string | null;
  readonly declaredTests: number;
}

/** The deterministic certification report object (the JSON shape). */
export interface CertificationReport {
  readonly schemaVersion: '1';
  readonly generator: string;
  /** Canonical rows, sorted by (category, testId). */
  readonly rows: readonly CertificationRow[];
  readonly totals: {
    readonly total: number;
    readonly pass: number;
    readonly fail: number;
    readonly notTested: number;
  };
  readonly lanes: readonly LaneSummary[];
  readonly categories: readonly CategoryTally[];
}

/** Canonical row order: category, then testId (stable, total). */
function canonicalRowSort(a: CertificationRow, b: CertificationRow): number {
  if (a.category !== b.category) return a.category < b.category ? -1 : 1;
  if (a.testId !== b.testId) return a.testId < b.testId ? -1 : 1;
  return 0;
}

/** A lane's declared shape, carried into the report's lane summaries. */
export interface LaneInput {
  readonly lane: LaneResult;
  readonly declaredTests: number;
}

/**
 * Assemble the deterministic report. Same inputs → byte-identical JSON:
 * rows canonically sorted by (category, testId); lane summaries follow the
 * INPUT lane order (the driver's fixed declaration order); categories are
 * sorted by name. No timestamps, no durations, no run-order dependence.
 */
export function assembleReport(laneInputs: readonly LaneInput[]): CertificationReport {
  // Resolve duplicates/conflicts over the whole row set, with attribution.
  const entries: LaneEntry[] = [];
  for (const input of laneInputs) {
    for (const row of input.lane.rows) entries.push({ row, laneId: input.lane.laneId });
  }
  const resolved = resolveDuplicateEntries(entries);

  // Canonical sort of the resolved rows, carrying lane attribution along.
  const sorted = resolved.rows
    .map((row, index) => ({ row, laneId: resolved.laneIds[index] }))
    .sort((a, b) => canonicalRowSort(a.row, b.row));

  // Lane summaries in input order (deterministic: driver declaration order).
  const laneSummaries: LaneSummary[] = laneInputs.map((input) => {
    const rowsOfLane = sorted.filter((entry) => entry.laneId === input.lane.laneId);
    let pass = 0;
    let fail = 0;
    let notTested = 0;
    for (const entry of rowsOfLane) {
      if (entry.row.result === 'PASS') pass += 1;
      else if (entry.row.result === 'FAIL') fail += 1;
      else notTested += 1;
    }
    return Object.freeze({
      laneId: input.lane.laneId,
      rowCount: rowsOfLane.length,
      pass,
      fail,
      notTested,
      collapsed: input.lane.collapsed,
      collapseCode: input.lane.collapseCode,
      declaredTests: input.declaredTests,
    });
  });

  // Totals + per-category tallies from the resolved, sorted rows.
  let pass = 0;
  let fail = 0;
  let notTested = 0;
  const categoryOrder: string[] = [];
  const categoryMap = new Map<string, { total: number; pass: number; fail: number; notTested: number }>();
  for (const entry of sorted) {
    const row = entry.row;
    let tally = categoryMap.get(row.category);
    if (!tally) {
      tally = { total: 0, pass: 0, fail: 0, notTested: 0 };
      categoryMap.set(row.category, tally);
      categoryOrder.push(row.category);
    }
    tally.total += 1;
    if (row.result === 'PASS') { tally.pass += 1; pass += 1; }
    else if (row.result === 'FAIL') { tally.fail += 1; fail += 1; }
    else { tally.notTested += 1; notTested += 1; }
  }
  const categories = categoryOrder
    .map((category) => Object.freeze({ category, ...categoryMap.get(category)! }))
    .sort((a, b) => (a.category < b.category ? -1 : a.category > b.category ? 1 : 0));

  return Object.freeze({
    schemaVersion: '1' as const,
    generator: 'certification-reporter/1 (Stop Point 10)',
    rows: Object.freeze(sorted.map((entry) => entry.row)),
    totals: Object.freeze({ total: sorted.length, pass, fail, notTested }),
    lanes: Object.freeze(laneSummaries),
    categories: Object.freeze(categories),
  });
}

// ---------------------------------------------------------------------------
// Verification (the committed artifact must hold every invariant)
// ---------------------------------------------------------------------------

/** The report's verification verdict. */
export interface VerificationResult {
  readonly ok: boolean;
  /** Violation codes (closed vocabulary, never content). */
  readonly violations: readonly string[];
}

const CERT_JSON_KEYS = new Set<string>(['schemaVersion', 'generator', 'rows', 'totals', 'lanes', 'categories']);
const CERT_ROW_KEYS = new Set<string>(['testId', 'category', 'requirement', 'result', 'reasonCode', 'sourceFile']);
const CERT_LANE_KEYS = new Set<string>(['laneId', 'rowCount', 'pass', 'fail', 'notTested', 'collapsed', 'collapseCode', 'declaredTests']);
const CERT_CATEGORY_KEYS = new Set<string>(['category', 'total', 'pass', 'fail', 'notTested']);

/**
 * Verify a report object against every invariant: shape, closed key sets,
 * reason-code safety, totals arithmetic (rows vs totals vs lanes vs
 * categories), canonical ordering, and metadata-only discipline. Violations
 * are listed by CODE only — never content.
 */
export function verifyReport(report: unknown): VerificationResult {
  const violations: string[] = [];
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    return { ok: false, violations: Object.freeze(['REPORT_NOT_OBJECT']) };
  }
  const r = report as Record<string, unknown>;

  for (const key of Object.keys(r)) {
    if (!CERT_JSON_KEYS.has(key)) violations.push('REPORT_UNKNOWN_KEY');
  }
  if (r.schemaVersion !== '1') violations.push('REPORT_SCHEMA_VERSION_INVALID');
  if (typeof r.generator !== 'string' || !r.generator.startsWith('certification-reporter/1')) {
    violations.push('REPORT_GENERATOR_INVALID');
  }
  if (!Array.isArray(r.rows)) return { ok: false, violations: Object.freeze([...violations, 'REPORT_ROWS_NOT_ARRAY']) };
  if (!Array.isArray(r.lanes)) return { ok: false, violations: Object.freeze([...violations, 'REPORT_LANES_NOT_ARRAY']) };
  if (!Array.isArray(r.categories)) return { ok: false, violations: Object.freeze([...violations, 'REPORT_CATEGORIES_NOT_ARRAY']) };

  // Rows: shape + safety + uniqueness.
  let pass = 0;
  let fail = 0;
  let notTested = 0;
  const seenIds = new Set<string>();
  for (const row of r.rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) { violations.push('ROW_NOT_OBJECT'); continue; }
    const rr = row as Record<string, unknown>;
    for (const key of Object.keys(rr)) {
      if (!CERT_ROW_KEYS.has(key)) violations.push('ROW_UNKNOWN_KEY');
    }
    if (typeof rr.testId !== 'string' || rr.testId === '') { violations.push('ROW_TESTID_INVALID'); continue; }
    if (seenIds.has(rr.testId)) violations.push('ROW_TESTID_DUPLICATE');
    seenIds.add(rr.testId);
    if (typeof rr.category !== 'string' || rr.category === '') violations.push('ROW_CATEGORY_INVALID');
    if (typeof rr.requirement !== 'string' || rr.requirement === '') violations.push('ROW_REQUIREMENT_INVALID');
    if (rr.result !== 'PASS' && rr.result !== 'FAIL' && rr.result !== 'NOT-TESTED') violations.push('ROW_RESULT_INVALID');
    if (rr.result === 'PASS' && (rr.reasonCode === null || rr.reasonCode === undefined)) violations.push('ROW_PASS_WITHOUT_REASON_CODE');
    if (rr.reasonCode !== null && rr.reasonCode !== undefined) {
      if (typeof rr.reasonCode !== 'string') violations.push('ROW_REASON_CODE_UNSAFE');
      else {
        if (!REASON_CODE_PATTERN.test(rr.reasonCode)) violations.push('ROW_REASON_CODE_UNSAFE');
        if (rr.reasonCode.length > CERTIFICATION_LIMITS.REASON_CODE_MAX) violations.push('ROW_REASON_CODE_TOO_LONG');
      }
    }
    if (typeof rr.sourceFile !== 'string' || rr.sourceFile === '') violations.push('ROW_SOURCEFILE_INVALID');
    if (typeof rr.testId === 'string' && rr.testId.length > CERTIFICATION_LIMITS.FIELD_MAX) violations.push('ROW_TESTID_TOO_LONG');
    if (typeof rr.requirement === 'string' && rr.requirement.length > CERTIFICATION_LIMITS.FIELD_MAX) violations.push('ROW_REQUIREMENT_TOO_LONG');
    if (rr.result === 'PASS') pass += 1;
    else if (rr.result === 'FAIL') fail += 1;
    else if (rr.result === 'NOT-TESTED') notTested += 1;
  }

  // Totals arithmetic.
  const t = r.totals;
  if (!t || typeof t !== 'object' || Array.isArray(t)) {
    violations.push('REPORT_TOTALS_INVALID');
  } else {
    const tt = t as Record<string, unknown>;
    if (tt.total !== r.rows.length) violations.push('TOTALS_TOTAL_MISMATCH');
    if (tt.pass !== pass) violations.push('TOTALS_PASS_MISMATCH');
    if (tt.fail !== fail) violations.push('TOTALS_FAIL_MISMATCH');
    if (tt.notTested !== notTested) violations.push('TOTALS_NOTTESTED_MISMATCH');
  }

  // Lanes: shape + arithmetic vs rows.
  let laneRowTotal = 0;
  let lanePass = 0;
  let laneFail = 0;
  let laneNotTested = 0;
  for (const lane of r.lanes) {
    if (!lane || typeof lane !== 'object' || Array.isArray(lane)) { violations.push('LANE_NOT_OBJECT'); continue; }
    const ll = lane as Record<string, unknown>;
    for (const key of Object.keys(ll)) {
      if (!CERT_LANE_KEYS.has(key)) violations.push('LANE_UNKNOWN_KEY');
    }
    if (typeof ll.laneId !== 'string' || ll.laneId === '') { violations.push('LANE_ID_INVALID'); continue; }
    if (typeof ll.rowCount !== 'number' || !Number.isInteger(ll.rowCount) || ll.rowCount < 0) violations.push('LANE_ROWCOUNT_INVALID');
    if (typeof ll.pass !== 'number' || typeof ll.fail !== 'number' || typeof ll.notTested !== 'number') {
      violations.push('LANE_COUNTS_INVALID');
    } else if (ll.rowCount !== ll.pass + ll.fail + ll.notTested) {
      violations.push('LANE_ARITHMETIC_MISMATCH');
    }
    if (ll.collapsed !== true && ll.collapsed !== false) violations.push('LANE_COLLAPSED_INVALID');
    if (ll.collapsed === true && (typeof ll.collapseCode !== 'string' || ll.collapseCode === '')) violations.push('LANE_COLLAPSE_CODE_INVALID');
    if (ll.collapsed === false && ll.collapseCode !== null) violations.push('LANE_COLLAPSE_CODE_PRESENT');
    if (typeof ll.declaredTests !== 'number' || !Number.isInteger(ll.declaredTests) || ll.declaredTests < 0) violations.push('LANE_DECLAREDTESTS_INVALID');
    if (typeof ll.rowCount === 'number') laneRowTotal += ll.rowCount;
    if (typeof ll.pass === 'number') lanePass += ll.pass;
    if (typeof ll.fail === 'number') laneFail += ll.fail;
    if (typeof ll.notTested === 'number') laneNotTested += ll.notTested;
  }
  if (laneRowTotal !== r.rows.length) violations.push('LANES_VS_ROWS_MISMATCH');
  if (lanePass !== pass) violations.push('LANES_VS_TOTALS_PASS_MISMATCH');
  if (laneFail !== fail) violations.push('LANES_VS_TOTALS_FAIL_MISMATCH');
  if (laneNotTested !== notTested) violations.push('LANES_VS_TOTALS_NOTTESTED_MISMATCH');

  // Categories: shape + arithmetic vs rows + ordering + uniqueness.
  let categoryRowTotal = 0;
  const seenCategories = new Set<string>();
  for (const category of r.categories) {
    if (!category || typeof category !== 'object' || Array.isArray(category)) { violations.push('CATEGORY_NOT_OBJECT'); continue; }
    const cc = category as Record<string, unknown>;
    for (const key of Object.keys(cc)) {
      if (!CERT_CATEGORY_KEYS.has(key)) violations.push('CATEGORY_UNKNOWN_KEY');
    }
    if (typeof cc.category !== 'string' || cc.category === '') { violations.push('CATEGORY_NAME_INVALID'); continue; }
    if (seenCategories.has(cc.category)) violations.push('CATEGORY_DUPLICATE');
    seenCategories.add(cc.category);
    if (typeof cc.total === 'number' && typeof cc.pass === 'number'
      && typeof cc.fail === 'number' && typeof cc.notTested === 'number'
      && cc.total !== cc.pass + cc.fail + cc.notTested) {
      violations.push('CATEGORY_ARITHMETIC_MISMATCH');
    }
    if (typeof cc.total === 'number') categoryRowTotal += cc.total;
  }
  if (categoryRowTotal !== r.rows.length) violations.push('CATEGORIES_VS_ROWS_MISMATCH');
  if (r.categories.length > 1) {
    for (let i = 1; i < r.categories.length; i += 1) {
      const prev = (r.categories[i - 1] as Record<string, unknown>).category;
      const cur = (r.categories[i] as Record<string, unknown>).category;
      if (typeof prev === 'string' && typeof cur === 'string' && prev >= cur) { violations.push('CATEGORY_ORDER_INVALID'); break; }
    }
  }

  // Canonical row ordering: (category, testId) strictly increasing.
  if (r.rows.length > 1) {
    let prev: { category: string; testId: string } | null = null;
    for (const row of r.rows) {
      const rr = row as { category?: unknown; testId?: unknown };
      if (typeof rr.category !== 'string' || typeof rr.testId !== 'string') continue;
      if (prev && (prev.category > rr.category || (prev.category === rr.category && prev.testId >= rr.testId))) {
        violations.push('ROWS_NOT_CANONICALLY_SORTED');
        break;
      }
      prev = { category: rr.category, testId: rr.testId };
    }
  }

  return { ok: violations.length === 0, violations: Object.freeze(violations) };
}

// ---------------------------------------------------------------------------
// The no-leak sweep over every serialized artifact (SP8 discipline)
// ---------------------------------------------------------------------------

/**
 * True when any forbidden value (payload text or secret material) appears
 * as a substring of the serialized surface. Mirrors the SP8
 * `containsSensitiveMaterial` semantics: values of meaningful length
 * participate; the caller sweeps the synthetic sandbox secrets and payload
 * markers, never anything real.
 */
export function containsSensitiveMaterial(text: string, forbidden: readonly string[]): boolean {
  if (typeof text !== 'string') return false;
  for (const value of forbidden) {
    if (typeof value === 'string' && value.length >= 8 && text.includes(value)) {
      return true;
    }
  }
  return false;
}

/** Assert the serialized artifacts are metadata-only; throw with the SURFACE LABEL only. */
export function assertMetadataOnly(
  serializedReport: string,
  serializedHtml: string,
  forbidden: readonly string[],
): void {
  if (containsSensitiveMaterial(serializedReport, forbidden)) {
    throw new Error('CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_JSON');
  }
  if (containsSensitiveMaterial(serializedHtml, forbidden)) {
    throw new Error('CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_HTML');
  }
}

// ---------------------------------------------------------------------------
// Self-contained static HTML rendering
// ---------------------------------------------------------------------------

const esc = (s: string): string => String(s ?? '')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#39;');

const RESULT_CLASS: Record<CertificationResult, string> = {
  PASS: 'r-pass',
  FAIL: 'r-fail',
  'NOT-TESTED': 'r-nt',
};

const STAT_CLASS: Record<string, string> = {
  TOTAL: '',
  PASS: 'pass',
  FAIL: 'fail',
  'NOT-TESTED': 'nt',
};

/**
 * Render the report as ONE self-contained HTML page: inline CSS only, no
 * scripts, no external assets, no network at render or view time. FAIL and
 * NOT-TESTED rows render in a dedicated "attention" section first so they
 * are visible, never buried. Byte-deterministic from the report object.
 */
export function renderReportHtml(report: CertificationReport): string {
  const resultBadge = (result: CertificationResult): string =>
    `<span class="badge ${RESULT_CLASS[result]}">${esc(result)}</span>`;

  const summaryRow = (label: string, value: number): string => {
    const cls = STAT_CLASS[label] ?? '';
    return `    <div class="stat"><div class="stat-num ${cls}">${value}</div><div class="stat-label">${esc(label)}</div></div>`;
  };

  const laneRow = (lane: LaneSummary): string => {
    const status = lane.collapsed
      ? `<span class="badge r-fail">COLLAPSED</span> <span class="mono">${esc(lane.collapseCode ?? '')}</span>`
      : lane.fail > 0
        ? '<span class="badge r-fail">FAIL</span>'
        : lane.notTested > 0
          ? '<span class="badge r-nt">NOT-TESTED</span>'
          : '<span class="badge r-pass">GREEN</span>';
    return `    <tr><td class="mono">${esc(lane.laneId)}</td><td>${lane.rowCount}</td><td>${lane.pass}</td><td>${lane.fail}</td><td>${lane.notTested}</td><td>${lane.declaredTests}</td><td>${status}</td></tr>`;
  };

  const categoryRow = (tally: CategoryTally): string => {
    const status = tally.fail > 0
      ? '<span class="badge r-fail">FAIL</span>'
      : tally.notTested > 0
        ? '<span class="badge r-nt">NOT-TESTED</span>'
        : '<span class="badge r-pass">GREEN</span>';
    return `    <tr><td class="mono">${esc(tally.category)}</td><td>${tally.total}</td><td>${tally.pass}</td><td>${tally.fail}</td><td>${tally.notTested}</td><td>${status}</td></tr>`;
  };

  const rowLine = (row: CertificationRow): string => {
    const reason = row.reasonCode === null ? '—' : esc(row.reasonCode);
    return `    <tr><td class="mono">${esc(row.testId)}</td><td class="mono">${esc(row.category)}</td><td>${esc(row.requirement)}</td><td>${resultBadge(row.result)}</td><td class="mono">${reason}</td><td class="mono">${esc(row.sourceFile)}</td></tr>`;
  };

  const failedRows = report.rows.filter((row) => row.result === 'FAIL');
  const notTestedRows = report.rows.filter((row) => row.result === 'NOT-TESTED');

  const attentionSection = failedRows.length + notTestedRows.length > 0
    ? `
  <h2>Attention required — FAIL and NOT-TESTED rows</h2>
  <p class="sub">${failedRows.length} FAIL row${failedRows.length === 1 ? '' : 's'} and ${notTestedRows.length} NOT-TESTED row${notTestedRows.length === 1 ? '' : 's'} require owner attention. The reporter records; the lanes gate CI.</p>
  <table class="tbl">
    <thead><tr><th>testId</th><th>category</th><th>requirement</th><th>result</th><th>reasonCode</th><th>sourceFile</th></tr></thead>
    <tbody>
${[...failedRows, ...notTestedRows].map(rowLine).join('\n')}
    </tbody>
  </table>
`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Certification Report — arma-partner-api-sandbox</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 0 0 48px; font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; color: #1f2328; background: #fff; }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 40px 24px 0; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 19px; margin: 40px 0 10px; padding-bottom: 6px; border-bottom: 1px solid #d1d9e0; }
  .sub { color: #59636e; font-size: 13.5px; margin: 0 0 18px; }
  .stats { display: flex; flex-wrap: wrap; gap: 12px; margin: 18px 0 8px; }
  .stat { flex: 1 1 130px; min-width: 130px; border: 1px solid #d1d9e0; border-radius: 8px; padding: 14px 16px; text-align: center; }
  .stat-num { font-size: 26px; font-weight: 700; }
  .stat-num.pass { color: #1a7f37; }
  .stat-num.fail { color: #cf222e; }
  .stat-num.nt { color: #9a6700; }
  .stat-label { font-size: 11px; letter-spacing: .06em; color: #59636e; margin-top: 2px; }
  .tbl { width: 100%; border-collapse: collapse; font-size: 13px; margin: 12px 0 8px; }
  .tbl th { text-align: left; padding: 8px 10px; background: #f6f8fa; border: 1px solid #d1d9e0; font-size: 12px; }
  .tbl td { padding: 7px 10px; border: 1px solid #d1d9e0; vertical-align: top; }
  .tbl tr:nth-child(even) td { background: #fbfdff; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; letter-spacing: .02em; }
  .r-pass { background: #dafbe1; color: #116329; }
  .r-fail { background: #ffebe9; color: #82071e; }
  .r-nt { background: #fff8c5; color: #7d4e00; }
  p.note { font-size: 13px; color: #59636e; margin-top: 28px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Certification Report</h1>
  <p class="sub">arma-partner-api-sandbox — Stop Point 10 integration certification. Every requirement-level PASS / FAIL / NOT-TESTED result, aggregated from every test lane. Deterministic: regenerated from the same tree on every CI run.</p>
  <div class="stats">
${summaryRow('TOTAL', report.totals.total)}
${summaryRow('PASS', report.totals.pass)}
${summaryRow('FAIL', report.totals.fail)}
${summaryRow('NOT-TESTED', report.totals.notTested)}
  </div>
${attentionSection}
  <h2>Lanes</h2>
  <p class="sub">Per-lane collection state. A collapsed lane failed closed to NOT-TESTED with a typed code — never a crash, never a silent skip.</p>
  <table class="tbl">
    <thead><tr><th>lane</th><th>rows</th><th>PASS</th><th>FAIL</th><th>NOT-TESTED</th><th>declared</th><th>state</th></tr></thead>
    <tbody>
${report.lanes.map(laneRow).join('\n')}
    </tbody>
  </table>
  <h2>Categories</h2>
  <p class="sub">PASS / FAIL / NOT-TESTED tallies per certification category.</p>
  <table class="tbl">
    <thead><tr><th>category</th><th>total</th><th>PASS</th><th>FAIL</th><th>NOT-TESTED</th><th>state</th></tr></thead>
    <tbody>
${report.categories.map(categoryRow).join('\n')}
    </tbody>
  </table>
  <h2>All certified rows</h2>
  <p class="sub">Every requirement in the report, canonically sorted by category then testId.</p>
  <table class="tbl">
    <thead><tr><th>testId</th><th>category</th><th>requirement</th><th>result</th><th>reasonCode</th><th>sourceFile</th></tr></thead>
    <tbody>
${report.rows.map(rowLine).join('\n')}
    </tbody>
  </table>
  <p class="note">Generated by <code class="mono">scripts/generate-certification-report.mjs</code> (<code class="mono">pnpm run certify:generate</code>) and verified by <code class="mono">scripts/verify-certification-report.mjs</code> (<code class="mono">pnpm run certify:verify</code>) in CI. Rows are metadata-only: identifiers, categories, requirement text, results, safe reason codes, and source-file references — never payload content, never secrets. The reporter records; the lanes gate CI.</p>
</div>
</body>
</html>`;
}
