// Stop Point 10 — certification reporter POSITIVE lane.
//
// Verifies the reporter engine end-to-end on synthetic-but-realistic lane
// evidence: TAP parsing against node:test's real output shapes, the row
// mapping, coercion of SP8-shaped rows, lane collection, duplicate
// resolution, deterministic assembly, full verification, the self-contained
// HTML rendering, and the metadata-only sweep. The fail-closed NEGATIVE
// paths live in certify.negative.test.mjs.

import test from 'node:test';
import assert from 'node:assert/strict';

import * as certify from '../certify.ts';

// ---------------------------------------------------------------------------
// Helpers — synthetic TAP in node:test's real output shape.
// ---------------------------------------------------------------------------

const tapOk = (n, name) => `ok ${n} - ${name}`;
const tapNotOk = (n, name) => `not ok ${n} - ${name}`;
const tapYamlBlock = () => '  ---\n  duration_ms: 1.25\n  type: \'test\'\n  ...';

function buildTap(rows) {
  const lines = ['TAP version 13'];
  let n = 0;
  for (const row of rows) {
    n += 1;
    lines.push(`# Subtest: ${row.name}`);
    lines.push(row.ok ? tapOk(n, row.name) : tapNotOk(n, row.name));
    lines.push(tapYamlBlock());
  }
  lines.push(`1..${rows.length}`);
  lines.push(`# tests ${rows.length}`);
  lines.push('# suites 0');
  lines.push(`# pass ${rows.filter((r) => r.ok).length}`);
  lines.push(`# fail ${rows.filter((r) => !r.ok).length}`);
  lines.push('# cancelled 0');
  lines.push('# skipped 0');
  lines.push('# todo 0');
  lines.push('# duration_ms 12.5');
  return lines.join('\n');
}

const SOURCE = 'synthetic/tests/lane.test.mjs';

// ---------------------------------------------------------------------------
// TAP parsing (real node:test output shapes)
// ---------------------------------------------------------------------------

test('parseTapStream parses a real-shaped green TAP stream with subtest headers and YAML blocks', () => {
  const tap = buildTap([
    { name: 'signs the request', ok: true },
    { name: 'verifies the receipt', ok: true },
    { name: 'replays are rejected', ok: true },
  ]);
  const parsed = certify.parseTapStream(tap);
  assert.equal(parsed.outcomes.length, 3);
  assert.equal(parsed.summary.tests, 3);
  assert.equal(parsed.summary.pass, 3);
  assert.equal(parsed.summary.fail, 0);
  assert.equal(parsed.wellFormed, true);
  assert.deepEqual(parsed.problems, []);
  for (const outcome of parsed.outcomes) {
    assert.equal(outcome.directive, 'none');
    assert.equal(outcome.ok, true);
    assert.equal(outcome.failureType, null);
    assert.equal(outcome.fileLevel, false);
  }
});

test('parseTapStream captures fail and skip and todo rows with their directives', () => {
  const tap = [
    'TAP version 13',
    'ok 1 - happy path works',
    'not ok 2 - failure path fails',
    'not ok 3 - unwired behavior # SKIP not wired in this sandbox',
    'not ok 4 - future behavior # TODO planned for a later stop point',
    '1..4',
    '# tests 4',
    '# pass 1',
    '# fail 1',
    '# cancelled 0',
    '# skipped 1',
    '# todo 1',
  ].join('\n');
  const parsed = certify.parseTapStream(tap);
  assert.equal(parsed.outcomes.length, 4);
  assert.equal(parsed.outcomes[2].directive, 'skip');
  assert.equal(parsed.outcomes[3].directive, 'todo');
  assert.equal(parsed.summary.skipped, 1);
  assert.equal(parsed.summary.todo, 1);
  assert.equal(parsed.wellFormed, true);
});

test('parseTapStream captures cancelled rows via the YAML failureType field only', () => {
  const tap = [
    'TAP version 13',
    'not ok 1 - hangs forever',
    '  ---',
    "  failureType: 'testTimeoutFailure'",
    '  ...',
    '1..1',
    '# tests 1',
    '# pass 0',
    '# fail 0',
    '# cancelled 1',
    '# skipped 0',
    '# todo 0',
  ].join('\n');
  const parsed = certify.parseTapStream(tap);
  assert.equal(parsed.outcomes[0].failureType, 'testTimeoutFailure');
  assert.equal(parsed.summary.cancelled, 1);
  assert.equal(parsed.wellFormed, true);
});

test('parseTapStream captures file-level load failures via the YAML exitCode field', () => {
  const tap = [
    'TAP version 13',
    'not ok 1 - synthetic/tests/broken.test.mjs',
    '  ---',
    '  exitCode: 1',
    '  ...',
    '1..1',
    '# tests 1',
    '# pass 0',
    '# fail 1',
    '# cancelled 0',
    '# skipped 0',
    '# todo 0',
  ].join('\n');
  const parsed = certify.parseTapStream(tap);
  assert.equal(parsed.outcomes[0].fileLevel, true);
  assert.equal(parsed.wellFormed, true);
});

test('parseTapStream discards all YAML detail except the two structural fields (no error text retained)', () => {
  const tap = [
    'TAP version 13',
    'not ok 1 - a failing test',
    '  ---',
    '  error: "synthetic-secret-bearing-message"',
    '  expected: \'x\'',
    '  actual: \'y\'',
    '  stack: |',
    '    at syntheticFrame (file.js:1:1)',
    '  ...',
    '1..1',
    '# tests 1',
    '# pass 0',
    '# fail 1',
    '# cancelled 0',
    '# skipped 0',
    '# todo 0',
  ].join('\n');
  const parsed = certify.parseTapStream(tap);
  assert.equal(parsed.outcomes.length, 1);
  assert.equal(parsed.outcomes[0].failureType, null);
  const serialized = JSON.stringify(parsed);
  assert.ok(!serialized.includes('synthetic-secret-bearing-message'));
  assert.ok(!serialized.includes('syntheticFrame'));
});

test('unescapeTapName and parseTapStream unescape TAP-escaped names exactly once', () => {
  assert.equal(certify.unescapeTapName('a \\# b'), 'a # b');
  assert.equal(certify.unescapeTapName('a \\\\ b'), 'a \\ b');
  const tap = [
    'TAP version 13',
    'ok 1 - rejects \\# injection attempts',
    '1..1',
    '# tests 1',
    '# pass 1',
    '# fail 0',
    '# cancelled 0',
    '# skipped 0',
    '# todo 0',
  ].join('\n');
  const parsed = certify.parseTapStream(tap);
  assert.equal(parsed.outcomes[0].name, 'rejects # injection attempts');
});

// ---------------------------------------------------------------------------
// TAP outcome -> row mapping
// ---------------------------------------------------------------------------

test('rowForTapOutcome maps a passing row to PASS with its expected code and a file-qualified testId', () => {
  const row = certify.rowForTapOutcome(
    { directive: 'none', ok: true, name: 'signs the request', failureType: null, fileLevel: false },
    certify.LANE_CATEGORIES.SHARED,
    SOURCE,
  );
  assert.equal(row.result, 'PASS');
  assert.equal(row.reasonCode, 'TEST_PASSED');
  assert.equal(row.category, 'SHARED');
  assert.equal(row.requirement, 'signs the request');
  assert.equal(row.testId, `${SOURCE}::signs the request`);
  assert.equal(row.sourceFile, SOURCE);
});

test('rowForTapOutcome maps a failing row to FAIL TEST_FAILED (visible, never buried)', () => {
  const row = certify.rowForTapOutcome(
    { directive: 'none', ok: false, name: 'rejects tampered envelopes', failureType: null, fileLevel: false },
    certify.LANE_CATEGORIES.LAW_SHIELD,
    SOURCE,
  );
  assert.equal(row.result, 'FAIL');
  assert.equal(row.reasonCode, 'TEST_FAILED');
});

test('rowForTapOutcome file-qualifies testIds so the same test name in two files stays two distinct rows', () => {
  const outcome = { directive: 'none', ok: true, name: 'verify fails closed when headers are missing', failureType: null, fileLevel: false };
  const a = certify.rowForTapOutcome(outcome, certify.LANE_CATEGORIES.SHARED, 'shared/tests/webhooks.test.mjs');
  const b = certify.rowForTapOutcome(outcome, certify.LANE_CATEGORIES.SHARED, 'shared/tests/sdk.receipts.test.mjs');
  assert.notEqual(a.testId, b.testId);
  assert.equal(a.result, 'PASS');
  assert.equal(b.result, 'PASS');
});

test('rowForTapOutcome caps oversized fields to the structural limits', () => {
  const longName = 'x'.repeat(400);
  const row = certify.rowForTapOutcome(
    { directive: 'none', ok: true, name: longName, failureType: null, fileLevel: false },
    certify.LANE_CATEGORIES.SHARED,
    SOURCE,
  );
  assert.equal(row.requirement.length, certify.CERTIFICATION_LIMITS.FIELD_MAX);
  assert.ok(row.testId.length <= certify.CERTIFICATION_LIMITS.FIELD_MAX);
});

// ---------------------------------------------------------------------------
// Row coercion (SP8 shape + evidence reference)
// ---------------------------------------------------------------------------

test('coerceRow accepts the SP8 certification-row shape verbatim plus the evidence reference', () => {
  const coerced = certify.coerceRow(
    {
      testId: 'sim-well-behaved:control',
      category: 'CONTROL',
      requirement: 'well-behaved simulator completes the full chain',
      result: 'PASS',
      reasonCode: 'OPERATION_COMPLETED',
    },
    'simulators/contractRunner.ts',
  );
  assert.equal(coerced.problem, null);
  assert.equal(coerced.row.result, 'PASS');
  assert.equal(coerced.row.reasonCode, 'OPERATION_COMPLETED');
  assert.equal(coerced.row.sourceFile, 'simulators/contractRunner.ts');
  assert.equal(coerced.row.category, 'CONTROL');
});

test('coerceRow accepts a FAIL row carrying its observed failure code', () => {
  const coerced = certify.coerceRow(
    {
      testId: 'sim-flaky:signature.tamperSignature',
      category: 'SIGNATURE',
      requirement: 'tampered signatures are rejected',
      result: 'FAIL',
      reasonCode: 'SIGNATURE_SIGNATURE_MISMATCH',
    },
    'simulators/contractRunner.ts',
  );
  assert.equal(coerced.problem, null);
  assert.equal(coerced.row.result, 'FAIL');
});

test('coerceRow accepts a NOT-TESTED row with a null reason code', () => {
  const coerced = certify.coerceRow(
    {
      testId: 'sim-x:replay.stale',
      category: 'REPLAY',
      requirement: 'stale presentations are refused',
      result: 'NOT-TESTED',
      reasonCode: null,
    },
    'simulators/contractRunner.ts',
  );
  assert.equal(coerced.problem, null);
  assert.equal(coerced.row.result, 'NOT-TESTED');
  assert.equal(coerced.row.reasonCode, null);
});

// ---------------------------------------------------------------------------
// Lane collection
// ---------------------------------------------------------------------------

test('collectLane collects a green lane row-by-row with no problems', () => {
  const tap = buildTap([
    { name: 'alpha passes', ok: true },
    { name: 'beta passes', ok: true },
    { name: 'gamma passes', ok: true },
  ]);
  const lane = certify.collectLane({
    laneId: 'synthetic/tests/lane.test.mjs',
    category: certify.LANE_CATEGORIES.SHARED,
    tap,
    declaredTests: 3,
    sourceFiles: [SOURCE],
    runnerExit: 0,
  });
  assert.equal(lane.collapsed, false);
  assert.equal(lane.collapseCode, null);
  assert.deepEqual(lane.problems, []);
  assert.equal(lane.rows.length, 3);
  for (const row of lane.rows) {
    assert.equal(row.result, 'PASS');
    assert.equal(row.reasonCode, 'TEST_PASSED');
  }
});

test('collectLane keeps a failing lane uncollapsed with its FAIL rows visible', () => {
  const tap = buildTap([
    { name: 'alpha passes', ok: true },
    { name: 'beta fails', ok: false },
  ]);
  const lane = certify.collectLane({
    laneId: 'synthetic/tests/lane.test.mjs',
    category: certify.LANE_CATEGORIES.SHARED,
    tap,
    declaredTests: 2,
    sourceFiles: [SOURCE],
    runnerExit: 1,
  });
  assert.equal(lane.collapsed, false);
  assert.equal(lane.rows[1].result, 'FAIL');
  assert.equal(lane.rows[1].reasonCode, 'TEST_FAILED');
});

test('laneFromRows and collapsedInProcessLane produce well-shaped in-process lanes', () => {
  const rows = [
    certify.rowForTapOutcome({ directive: 'none', ok: true, name: 'r', failureType: null, fileLevel: false }, 'SHARED', SOURCE),
  ];
  const good = certify.laneFromRows('simulators-matrix', rows);
  assert.equal(good.collapsed, false);
  assert.equal(good.rows.length, 1);

  const collapsed = certify.collapsedInProcessLane('simulators-matrix', 'SIMULATORS_MATRIX', 'LANE_COUNT_MISMATCH');
  assert.equal(collapsed.collapsed, true);
  assert.equal(collapsed.collapseCode, 'LANE_COUNT_MISMATCH');
  assert.equal(collapsed.rows.length, 1);
  assert.equal(collapsed.rows[0].result, 'NOT-TESTED');
});

// ---------------------------------------------------------------------------
// Duplicate resolution + deterministic assembly
// ---------------------------------------------------------------------------

test('resolveDuplicates keeps same-name rows from different files distinct (no false duplicate)', () => {
  const outcome = { directive: 'none', ok: true, name: 'verify fails closed when headers are missing', failureType: null, fileLevel: false };
  const rows = [
    certify.rowForTapOutcome(outcome, certify.LANE_CATEGORIES.SHARED, 'shared/tests/webhooks.test.mjs'),
    certify.rowForTapOutcome(outcome, certify.LANE_CATEGORIES.SHARED, 'shared/tests/sdk.receipts.test.mjs'),
  ];
  const resolved = certify.resolveDuplicates(rows);
  assert.equal(resolved.rows.length, 2);
  assert.equal(resolved.duplicateCount, 0);
  assert.equal(resolved.conflictCount, 0);
  for (const row of resolved.rows) assert.equal(row.result, 'PASS');
});

function greenLane(laneId, category, names, sourceFile) {
  const tap = buildTap(names.map((name) => ({ name, ok: true })));
  return certify.collectLane({
    laneId,
    category,
    tap,
    declaredTests: names.length,
    sourceFiles: [sourceFile],
    runnerExit: 0,
  });
}

test('assembleReport builds a verifying report with consistent totals, lanes, and categories', () => {
  const laneInputs = [
    { lane: greenLane('shared/tests/a.test.mjs', certify.LANE_CATEGORIES.SHARED, ['a one', 'a two'], 'shared/tests/a.test.mjs'), declaredTests: 2 },
    { lane: greenLane('law-shield/tests/b.test.mjs', certify.LANE_CATEGORIES.LAW_SHIELD, ['b one'], 'law-shield/tests/b.test.mjs'), declaredTests: 1 },
  ];
  const report = certify.assembleReport(laneInputs);
  assert.equal(report.totals.total, 3);
  assert.equal(report.totals.pass, 3);
  assert.equal(report.totals.fail, 0);
  assert.equal(report.totals.notTested, 0);
  assert.equal(report.lanes.length, 2);
  assert.equal(report.categories.length, 2);
  assert.equal(report.schemaVersion, '1');
  const verdict = certify.verifyReport(report);
  assert.equal(verdict.ok, true, JSON.stringify(verdict.violations));
});

test('assembleReport is byte-deterministic: identical inputs serialize identically with no timestamps', () => {
  const laneInputs = () => [
    { lane: greenLane('shared/tests/a.test.mjs', certify.LANE_CATEGORIES.SHARED, ['a one', 'a two'], 'shared/tests/a.test.mjs'), declaredTests: 2 },
    { lane: greenLane('simulators/tests/b.test.mjs', certify.LANE_CATEGORIES.SIMULATORS, ['b one'], 'simulators/tests/b.test.mjs'), declaredTests: 1 },
  ];
  const one = certify.assembleReport(laneInputs());
  const two = certify.assembleReport(laneInputs());
  assert.equal(JSON.stringify(one), JSON.stringify(two));
  assert.ok(!JSON.stringify(one).includes('Date'));
  assert.ok(!/duration|timestamp|generatedAt/i.test(JSON.stringify(one)));
});

test('assembleReport sorts rows canonically by category then testId and categories by name', () => {
  const laneInputs = [
    { lane: greenLane('z.test.mjs', 'SHARED', ['zz row', 'aa row'], 'z.test.mjs'), declaredTests: 2 },
    { lane: greenLane('y.test.mjs', 'CONTROL', ['cc row'], 'y.test.mjs'), declaredTests: 1 },
  ];
  const report = certify.assembleReport(laneInputs);
  const categories = report.rows.map((row) => row.category);
  assert.deepEqual([...categories].sort(), categories);
  assert.equal(report.rows[0].category, 'CONTROL');
  assert.ok(report.categories.every((tally, i, all) => i === 0 || all[i - 1].category < tally.category));
});

test('assembleReport round-trips through JSON with verification intact', () => {
  const laneInputs = [
    { lane: greenLane('shared/tests/a.test.mjs', certify.LANE_CATEGORIES.SHARED, ['a one'], 'shared/tests/a.test.mjs'), declaredTests: 1 },
  ];
  const report = certify.assembleReport(laneInputs);
  const roundTripped = JSON.parse(JSON.stringify(report));
  const verdict = certify.verifyReport(roundTripped);
  assert.equal(verdict.ok, true, JSON.stringify(verdict.violations));
});

// ---------------------------------------------------------------------------
// The SP8 contract matrix as an in-process lane (the driver-equivalent path)
// ---------------------------------------------------------------------------

test('the SP8 contract matrix coerces row-by-row into verifiable certification rows, all PASS', async () => {
  const { runContractMatrix } = await import('../../simulators/contractRunner.ts');
  const summary = runContractMatrix({});
  assert.equal(summary.rows.length, 123);
  const rows = [];
  for (const raw of summary.rows) {
    const coerced = certify.coerceRow(raw, 'simulators/contractRunner.ts');
    assert.equal(coerced.problem, null);
    assert.ok(coerced.row !== null);
    rows.push(coerced.row);
  }
  const lane = certify.laneFromRows('simulators-matrix', rows);
  const report = certify.assembleReport([{ lane, declaredTests: 123 }]);
  assert.equal(report.totals.total, 123);
  assert.equal(report.totals.pass, 123);
  assert.equal(report.totals.fail, 0);
  const verdict = certify.verifyReport(report);
  assert.equal(verdict.ok, true, JSON.stringify(verdict.violations));
});

// ---------------------------------------------------------------------------
// HTML rendering (self-contained, deterministic, FAIL-visible)
// ---------------------------------------------------------------------------

test('renderReportHtml emits a self-contained page: inline CSS, no scripts, no external references', () => {
  const laneInputs = [
    { lane: greenLane('shared/tests/a.test.mjs', certify.LANE_CATEGORIES.SHARED, ['a one'], 'shared/tests/a.test.mjs'), declaredTests: 1 },
  ];
  const html = certify.renderReportHtml(certify.assembleReport(laneInputs));
  assert.ok(html.startsWith('<!doctype html>'));
  assert.ok(html.includes('<style>'));
  assert.ok(!html.includes('<script'));
  assert.ok(!/<link[^>]+href=/.test(html));
  assert.ok(!/src=["']https?:/.test(html));
  assert.ok(!/href=["']https?:/.test(html));
});

test('renderReportHtml is byte-deterministic and renders every row', () => {
  const laneInputs = () => [
    { lane: greenLane('shared/tests/a.test.mjs', certify.LANE_CATEGORIES.SHARED, ['a one', 'a two'], 'shared/tests/a.test.mjs'), declaredTests: 2 },
  ];
  const one = certify.renderReportHtml(certify.assembleReport(laneInputs()));
  const two = certify.renderReportHtml(certify.assembleReport(laneInputs()));
  assert.equal(one, two);
  assert.ok(one.includes('shared/tests/a.test.mjs::a one'));
  assert.ok(one.includes('shared/tests/a.test.mjs::a two'));
});

test('renderReportHtml renders FAIL rows in the attention section first, never buried', () => {
  const rows = [
    certify.rowForTapOutcome({ directive: 'none', ok: true, name: 'good row', failureType: null, fileLevel: false }, 'SHARED', SOURCE),
    certify.rowForTapOutcome({ directive: 'none', ok: false, name: 'bad row', failureType: null, fileLevel: false }, 'SHARED', SOURCE),
  ];
  const report = certify.assembleReport([{ lane: certify.laneFromRows('shared', rows), declaredTests: 2 }]);
  const html = certify.renderReportHtml(report);
  const attentionIndex = html.indexOf('Attention required');
  const badIndex = html.indexOf('bad row');
  const allRowsIndex = html.indexOf('All certified rows');
  assert.ok(attentionIndex > -1);
  assert.ok(badIndex > attentionIndex);
  assert.ok(allRowsIndex > badIndex);
  assert.ok(html.slice(attentionIndex, allRowsIndex).includes('FAIL'));
});

// ---------------------------------------------------------------------------
// The no-leak sweep (synthetic fixtures)
// ---------------------------------------------------------------------------

test('containsSensitiveMaterial matches meaningful forbidden values and ignores short noise', () => {
  const forbidden = ['synthetic-secret-value-123456', 'tiny'];
  assert.equal(certify.containsSensitiveMaterial('text with synthetic-secret-value-123456 inside', forbidden), true);
  assert.equal(certify.containsSensitiveMaterial('text with tiny inside', forbidden), false);
  assert.equal(certify.containsSensitiveMaterial('clean text', forbidden), false);
});

test('assertMetadataOnly passes clean surfaces and throws surface labels only on a hit', () => {
  const forbidden = ['synthetic-secret-value-123456'];
  certify.assertMetadataOnly('{"rows":[]}', '<html>clean</html>', forbidden);
  assert.throws(
    () => certify.assertMetadataOnly('{"leak":"synthetic-secret-value-123456"}', '<html>clean</html>', forbidden),
    (err) => err.message === 'CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_JSON',
  );
  assert.throws(
    () => certify.assertMetadataOnly('{"rows":[]}', '<html>synthetic-secret-value-123456</html>', forbidden),
    (err) => err.message === 'CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_HTML',
  );
});

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

test('REPORTER_REASON_CODES is a closed UPPER_SNAKE vocabulary', () => {
  const values = Object.values(certify.REPORTER_REASON_CODES);
  for (const value of values) {
    assert.match(value, /^[A-Z][A-Z0-9_]*$/);
    assert.ok(value.length <= certify.CERTIFICATION_LIMITS.REASON_CODE_MAX);
  }
  assert.ok(values.includes('LANE_UNCOLLECTABLE'));
  assert.ok(values.includes('ROW_CONFLICTING_EVIDENCE'));
  assert.ok(values.includes('SENSITIVE_MATERIAL_DETECTED'));
});

test('LANE_CATEGORIES covers the lane, SP9, and SP8 matrix vocabularies', () => {
  const categories = Object.values(certify.LANE_CATEGORIES);
  for (const needed of [
    'LAW_SHIELD', 'PATCHES_CONTRACT', 'PATCHES_ADAPTER', 'AI_GOVERNANCE', 'SHARED', 'SIMULATORS', 'SIMULATORS_MATRIX',
    'OPENAPI_STRUCTURE', 'OPENAPI_CROSSCHECK', 'OPENAPI_LIVE_CONFORMANCE', 'CERTIFICATION', 'UNDECLARED',
    'CONTROL', 'SIGNATURE', 'REPLAY', 'RECEIPT', 'AUTHORIZATION', 'ENTITLEMENT', 'WEBHOOK', 'RETRY',
    'RECONCILIATION', 'CIRCUIT_BREAKER', 'KILL_SWITCH',
  ]) {
    assert.ok(categories.includes(needed), `missing category ${needed}`);
  }
});

test('CERTIFICATION_LIMITS is frozen with the committed structural limits', () => {
  assert.equal(Object.isFrozen(certify.CERTIFICATION_LIMITS), true);
  assert.equal(certify.CERTIFICATION_LIMITS.FIELD_MAX, 256);
  assert.equal(certify.CERTIFICATION_LIMITS.REASON_CODE_MAX, 128);
  assert.equal(certify.CERTIFICATION_LIMITS.SOURCE_FILE_MAX, 200);
});
