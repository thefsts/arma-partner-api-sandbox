#!/usr/bin/env node
// Stop Point 10 — the certification report generator (the driver).
//
// Runs every declared test lane per source file (per-file TAP, so every row
// carries an honest metadata-only sourceFile reference and file-level
// failures are attributed precisely), imports the SP8 contract matrix
// in-process, assembles the deterministic report through the fail-closed
// engine in certification/certify.ts, SELF-VERIFIES it, sweeps it for
// forbidden material, and only then writes the two committed artifacts:
//   docs/certification/certification-report.json  (machine-readable)
//   docs/certification/certification-report.html  (self-contained, owner-facing)
//
// Discipline (docs/STOP-POINT-9-REPORT.md §10, owner-approved):
//   * RECORDS, does not gate — a FAIL or NOT-TESTED row is printed and
//     rendered, never buried; the driver exits 0 so the owner sees the
//     record. CI's lockstep diff (regenerate + git diff --exit-code) is
//     what keeps the artifact honest with the tree.
//   * Exits NON-ZERO only on reporter-internal defects: self-verification
//     violations, a leak-sweep hit, or unavailable sweep fixtures. Those
//     mean the reporter itself is broken — a red gate, per the ERROR RULE.
//   * Deterministic: same tree + same lane evidence → byte-identical
//     artifacts (no timestamps, no durations, canonical row order, fixed
//     manifest order). CI regenerates and diffs to prove it.
//   * Fail-closed manifest: every declared count is cross-checked against
//     the lane's own TAP summary; drift collapses the lane visibly
//     (LANE_COUNT_MISMATCH). A manifest file missing from the tree
//     collapses with LANE_MISSING; a test file on disk that the manifest
//     does not declare collapses with LANE_UNDECLARED — no silent skips.

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');
const tsUrl = (relative) => pathToFileURL(join(repo, relative)).href;

const {
  LANE_CATEGORIES,
  REPORTER_REASON_CODES,
  assembleReport,
  assertMetadataOnly,
  coerceRow,
  collectLane,
  collapsedInProcessLane,
  laneFromRows,
  renderReportHtml,
  verifyReport,
} = await import(tsUrl('certification/certify.ts'));

// ---------------------------------------------------------------------------
// The committed manifest — the fail-closed declaration of every lane.
//
// Counts verified empirically against the per-file TAP of this tree. When a
// lane's test count drifts, collectLane collapses it with
// LANE_COUNT_MISMATCH and the CI lockstep diff fails — the owner updates
// the manifest deliberately, never silently.
// ---------------------------------------------------------------------------

const MANIFEST = Object.freeze([
  // law-shield (LAW_SHIELD, 71)
  { file: 'law-shield/tests/arma.transfer.test.mjs', category: LANE_CATEGORIES.LAW_SHIELD, declaredTests: 14 },
  { file: 'law-shield/tests/contract.compat.test.mjs', category: LANE_CATEGORIES.LAW_SHIELD, declaredTests: 4 },
  { file: 'law-shield/tests/e2e.synthetic.test.mjs', category: LANE_CATEGORIES.LAW_SHIELD, declaredTests: 1 },
  { file: 'law-shield/tests/gateway.security.test.mjs', category: LANE_CATEGORIES.LAW_SHIELD, declaredTests: 30 },
  { file: 'law-shield/tests/processor.durable.test.mjs', category: LANE_CATEGORIES.LAW_SHIELD, declaredTests: 22 },
  // patches (contract 30 + adapter 48)
  { file: 'patches/tests/partner.api.test.mjs', category: LANE_CATEGORIES.PATCHES_CONTRACT, declaredTests: 30 },
  { file: 'patches/tests/partner.client.test.mjs', category: LANE_CATEGORIES.PATCHES_ADAPTER, declaredTests: 48 },
  // ai-governance (AI_GOVERNANCE, 56)
  { file: 'ai-governance/tests/e2e.synthetic.test.mjs', category: LANE_CATEGORIES.AI_GOVERNANCE, declaredTests: 4 },
  { file: 'ai-governance/tests/governance.test.mjs', category: LANE_CATEGORIES.AI_GOVERNANCE, declaredTests: 10 },
  { file: 'ai-governance/tests/human-review.test.mjs', category: LANE_CATEGORIES.AI_GOVERNANCE, declaredTests: 4 },
  { file: 'ai-governance/tests/injection.test.mjs', category: LANE_CATEGORIES.AI_GOVERNANCE, declaredTests: 9 },
  { file: 'ai-governance/tests/protected-actions.test.mjs', category: LANE_CATEGORIES.AI_GOVERNANCE, declaredTests: 16 },
  { file: 'ai-governance/tests/provenance.test.mjs', category: LANE_CATEGORIES.AI_GOVERNANCE, declaredTests: 13 },
  // shared (SHARED, 207)
  { file: 'shared/tests/e2e.synthetic.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 11 },
  { file: 'shared/tests/observability.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 18 },
  { file: 'shared/tests/registry.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 17 },
  { file: 'shared/tests/sdk.audit.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 13 },
  { file: 'shared/tests/sdk.client.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 18 },
  { file: 'shared/tests/sdk.correlation.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 18 },
  { file: 'shared/tests/sdk.errors.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 15 },
  { file: 'shared/tests/sdk.health.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 12 },
  { file: 'shared/tests/sdk.idempotency.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 14 },
  { file: 'shared/tests/sdk.receipts.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 11 },
  { file: 'shared/tests/sdk.retries.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 14 },
  { file: 'shared/tests/sdk.signing.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 18 },
  { file: 'shared/tests/webhooks.test.mjs', category: LANE_CATEGORIES.SHARED, declaredTests: 28 },
  // simulators (SIMULATORS, 53)
  { file: 'simulators/tests/simulators.config-driven.test.mjs', category: LANE_CATEGORIES.SIMULATORS, declaredTests: 24 },
  { file: 'simulators/tests/simulators.contract-runner.test.mjs', category: LANE_CATEGORIES.SIMULATORS, declaredTests: 12 },
  { file: 'simulators/tests/simulators.failure-modes.test.mjs', category: LANE_CATEGORIES.SIMULATORS, declaredTests: 10 },
  { file: 'simulators/tests/simulators.happy-path.test.mjs', category: LANE_CATEGORIES.SIMULATORS, declaredTests: 7 },
]);

// The SP8 contract-matrix lane, imported and run in-process (deterministic,
// 60ms). Declared scenario count is committed: drift collapses visibly.
const MATRIX_LANE = Object.freeze({
  laneId: 'simulators-matrix',
  declaredTests: 123,
  source: 'simulators/contractRunner.ts',
});

// The openapi lane files, split by contract-test layer (SP9 categories).
const OPENAPI_MANIFEST = Object.freeze([
  { file: 'openapi/tests/spec.structure.test.mjs', category: LANE_CATEGORIES.OPENAPI_STRUCTURE, declaredTests: 2 },
  { file: 'openapi/tests/spec.crosscheck.test.mjs', category: LANE_CATEGORIES.OPENAPI_CROSSCHECK, declaredTests: 3 },
  { file: 'openapi/tests/spec.live-conformance.test.mjs', category: LANE_CATEGORIES.OPENAPI_LIVE_CONFORMANCE, declaredTests: 3 },
]);

// The certification reporter's own test lane (this stop point).
const CERTIFICATION_MANIFEST = Object.freeze([
  { file: 'certification/tests/certify.report.test.mjs', category: LANE_CATEGORIES.CERTIFICATION, declaredTests: 30 },
  { file: 'certification/tests/certify.negative.test.mjs', category: LANE_CATEGORIES.CERTIFICATION, declaredTests: 36 },
]);

// Every directory that may hold test files — swept for undeclared files.
const TEST_DIRS = Object.freeze([
  'law-shield/tests',
  'patches/tests',
  'ai-governance/tests',
  'shared/tests',
  'simulators/tests',
  'openapi/tests',
  'certification/tests',
]);

// ---------------------------------------------------------------------------
// Forbidden material for the no-leak sweep (synthetic sandbox fixtures only).
// If ANY fixture is unavailable the sweep cannot run → reporter-internal
// defect → exit non-zero (fail-closed: never write an unswept artifact).
// ---------------------------------------------------------------------------

async function loadForbiddenMaterial() {
  const forbidden = [];
  const behaviors = await import(tsUrl('simulators/behaviors.ts'));
  for (const value of Object.values(behaviors.SYNTHETIC_SIMULATOR_SECRETS)) {
    forbidden.push(String(value));
  }
  forbidden.push(String(behaviors.SYNTHETIC_WRONG_SIGNING_SECRET));
  for (const surface of ['SIGNATURE', 'REPLAY', 'RECEIPT', 'AUTHORIZATION', 'ENTITLEMENT', 'WEBHOOK', 'RETRY', 'RECONCILIATION']) {
    forbidden.push(String(behaviors.syntheticPayloadFor(surface)));
  }
  const servers = await import(tsUrl('law-shield/tests/helpers/servers.mjs'));
  forbidden.push(String(servers.GATEWAY_SECRET));
  forbidden.push(String(servers.RECEIPT_SECRET));
  forbidden.push(String(servers.PROCESSOR_TOKEN));
  return forbidden;
}

// ---------------------------------------------------------------------------
// Lane collection
// ---------------------------------------------------------------------------

function runFileLane(entry) {
  if (!existsSync(join(repo, entry.file))) {
    return collapsedInProcessLane(entry.file, entry.category, REPORTER_REASON_CODES.LANE_MISSING);
  }
  const result = spawnSync(
    process.execPath,
    ['--test', '--test-reporter=tap', entry.file],
    { cwd: repo, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 240_000 },
  );
  const tap = result.stdout ?? '';
  const runnerExit = result.status === null ? 1 : result.status;
  return collectLane({
    laneId: entry.file,
    category: entry.category,
    tap,
    declaredTests: entry.declaredTests,
    sourceFiles: [entry.file],
    runnerExit,
  });
}

async function runMatrixLane() {
  let summary;
  try {
    const { runContractMatrix } = await import(tsUrl(MATRIX_LANE.source));
    summary = runContractMatrix({});
  } catch {
    return collapsedInProcessLane(MATRIX_LANE.laneId, LANE_CATEGORIES.SIMULATORS_MATRIX, REPORTER_REASON_CODES.LANE_UNCOLLECTABLE);
  }
  if (summary.rows.length !== MATRIX_LANE.declaredTests) {
    return collapsedInProcessLane(MATRIX_LANE.laneId, LANE_CATEGORIES.SIMULATORS_MATRIX, REPORTER_REASON_CODES.LANE_COUNT_MISMATCH);
  }
  const rows = [];
  for (const raw of summary.rows) {
    const coerced = coerceRow(raw, MATRIX_LANE.source);
    if (coerced.row === null) {
      // Matrix evidence the reporter cannot fully interpret → lane collapse.
      return collapsedInProcessLane(MATRIX_LANE.laneId, LANE_CATEGORIES.SIMULATORS_MATRIX, REPORTER_REASON_CODES.ROW_MALFORMED);
    }
    rows.push(coerced.row);
  }
  return laneFromRows(MATRIX_LANE.laneId, rows);
}

function sweepForUndeclaredFiles(declared) {
  const results = [];
  for (const dir of TEST_DIRS) {
    const dirPath = join(repo, dir);
    if (!existsSync(dirPath)) continue;
    const found = readdirSync(dirPath)
      .filter((name) => name.endsWith('.test.mjs'))
      .sort()
      .map((name) => `${dir}/${name}`);
    for (const file of found) {
      if (!declared.has(file)) {
        results.push(file);
      }
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const failures = [];

try {
  const forbidden = await loadForbiddenMaterial();

  const declared = new Set(MANIFEST.map((e) => e.file));
  const openapiEntries = OPENAPI_MANIFEST;
  const certificationEntries = existsSync(join(repo, 'certification/tests'))
    ? CERTIFICATION_MANIFEST
    : [];
  for (const e of openapiEntries) declared.add(e.file);
  for (const e of certificationEntries) declared.add(e.file);

  console.log('=== Stop Point 10 — certification report generation ===');
  console.log(`no-leak sweep fixtures: ${forbidden.length} synthetic markers loaded`);

  const laneInputs = [];
  const laneOrder = [];

  const emit = (lane, declaredTests) => {
    laneInputs.push({ lane, declaredTests });
    laneOrder.push(lane.laneId);
  };

  for (const entry of MANIFEST) emit(runFileLane(entry), entry.declaredTests);
  emit(await runMatrixLane(), MATRIX_LANE.declaredTests);
  for (const entry of openapiEntries) emit(runFileLane(entry), entry.declaredTests);
  for (const entry of certificationEntries) emit(runFileLane(entry), entry.declaredTests);

  for (const file of sweepForUndeclaredFiles(declared)) {
    emit(
      collapsedInProcessLane(file, LANE_CATEGORIES.UNDECLARED, REPORTER_REASON_CODES.LANE_UNDECLARED),
      0,
    );
  }

  const report = assembleReport(laneInputs);

  // Per-lane stdout summary (counts and codes only — metadata discipline).
  for (const lane of report.lanes) {
    const state = lane.collapsed
      ? `COLLAPSED(${lane.collapseCode})`
      : lane.fail > 0 ? 'HAS FAIL ROWS' : lane.notTested > 0 ? 'HAS NOT-TESTED ROWS' : 'GREEN';
    console.log(
      `lane ${lane.laneId} — ${lane.rowCount} rows (${lane.pass} PASS / ${lane.fail} FAIL / ${lane.notTested} NOT-TESTED, declared ${lane.declaredTests}) [${state}]`,
    );
  }

  const attention = report.rows.filter((row) => row.result !== 'PASS');
  if (attention.length > 0) {
    console.log('--- ATTENTION (recorded, not gating) —');
    for (const row of attention) {
      console.log(`  [${row.result}] ${row.testId} — ${row.reasonCode ?? 'NO_CODE'}`);
    }
  }
  console.log(
    `totals: ${report.totals.total} rows — ${report.totals.pass} PASS / ${report.totals.fail} FAIL / ${report.totals.notTested} NOT-TESTED`,
  );

  // Self-verification BEFORE writing (reporter-internal gate).
  const verdict = verifyReport(report);
  if (!verdict.ok) {
    failures.push(`SELF_VERIFICATION_FAILED: ${verdict.violations.join(', ')}`);
  } else {
    console.log('self-verification: OK (0 violations)');
  }

  // Serialize deterministically, verify the round-trip, sweep, then write.
  const json = `${JSON.stringify(report, null, 2)}\n`;
  const roundTrip = verifyReport(JSON.parse(json));
  if (!roundTrip.ok) {
    failures.push(`ROUND_TRIP_VERIFICATION_FAILED: ${roundTrip.violations.join(', ')}`);
  }
  const html = renderReportHtml(report);

  try {
    assertMetadataOnly(json, html, forbidden);
    console.log('no-leak sweep: OK (artifacts are metadata-only)');
  } catch (err) {
    failures.push(`LEAK_SWEEP_FAILED: ${err.message}`);
  }

  if (failures.length === 0) {
    const outDir = join(repo, 'docs', 'certification');
    mkdirSync(outDir, { recursive: true });
    const jsonPath = join(outDir, 'certification-report.json');
    const htmlPath = join(outDir, 'certification-report.html');
    writeFileSync(jsonPath, json, 'utf8');
    writeFileSync(htmlPath, html, 'utf8');
    console.log(`written: docs/certification/certification-report.json (${Buffer.byteLength(json)} bytes)`);
    console.log(`written: docs/certification/certification-report.html (${Buffer.byteLength(html)} bytes)`);
    console.log('The reporter RECORDS; the lanes gate CI. A FAIL or NOT-TESTED row above is visible to the owner, never buried.');
  }
} catch (err) {
  failures.push(`REPORTER_INTERNAL_ERROR: ${err.message}`);
}

if (failures.length > 0) {
  console.error('--- REPORTER DEFECT (red gate) —');
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
process.exit(0);
