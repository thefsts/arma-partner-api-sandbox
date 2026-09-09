// Stop Point 10 — certification reporter NEGATIVE lane.
//
// Every fail-closed path, proven NEVER-PASS:
//   * missing evidence (empty/absent lanes, file-level load failures)
//   * malformed rows (unknown fields, unknown results, unsafe codes)
//   * failing rows (FAIL stays FAIL, visible)
//   * NOT-TESTED (skip/todo/cancelled directives)
//   * conflicting rows (same testId, different facts) -> FAIL
//   * duplicate identical rows -> NOT-TESTED
//   * lane collapse (count mismatch, uncollectable runner, crash)
//   * lane-withholding: a collapsed lane's PASS rows -> NOT-TESTED
//   * leak injection -> surface-label-only throw
//   * tamper detection: every mutation the verifier must catch.

import test from 'node:test';
import assert from 'node:assert/strict';

import * as certify from '../certify.ts';

const SOURCE = 'synthetic/tests/negative.test.mjs';

function buildTap(rows) {
  const lines = ['TAP version 13'];
  let n = 0;
  for (const row of rows) {
    n += 1;
    lines.push(row.ok ? `ok ${n} - ${row.name}` : `not ok ${n} - ${row.name}`);
    if (row.yaml) lines.push(...row.yaml);
    else if (row.ok) lines.push('  ---', "  duration_ms: 1.25", "  type: 'test'", '  ...');
  }
  lines.push(`1..${rows.length}`);
  lines.push(`# tests ${rows.length}`);
  lines.push('# suites 0');
  lines.push(`# pass ${rows.filter((r) => r.ok && !r.countedAsFail).length}`);
  lines.push(`# fail ${rows.filter((r) => !r.ok && !r.cancelled).length}`);
  lines.push(`# cancelled ${rows.filter((r) => r.cancelled).length}`);
  lines.push(`# skipped ${rows.filter((r) => r.skip).length}`);
  lines.push(`# todo ${rows.filter((r) => r.todo).length}`);
  return lines.join('\n');
}

function laneFor(tap, declaredTests, runnerExit) {
  return certify.collectLane({
    laneId: SOURCE,
    category: 'SHARED',
    tap,
    declaredTests,
    sourceFiles: [SOURCE],
    runnerExit,
  });
}

// ---------------------------------------------------------------------------
// Lane collapse — never PASS
// ---------------------------------------------------------------------------

test('a lane whose TAP is empty collapses to NOT-TESTED, never PASS (LANE_OUTPUT_EMPTY)', () => {
  const lane = laneFor('', 3, 0);
  assert.equal(lane.collapsed, true);
  assert.equal(lane.collapseCode, 'LANE_OUTPUT_EMPTY');
  assert.equal(lane.rows.length, 1);
  assert.equal(lane.rows[0].result, 'NOT-TESTED');
});

test('a lane with no plan and no counters collapses (TAP_PLAN_MISSING / TAP_COUNTERS_MISSING)', () => {
  const tap = ['TAP version 13', 'ok 1 - orphan row'].join('\n');
  const lane = laneFor(tap, 1, 0);
  assert.equal(lane.collapsed, true);
  assert.ok(lane.problems.includes('TAP_PLAN_MISSING'));
  assert.ok(lane.problems.includes('TAP_COUNTERS_MISSING'));
  for (const row of lane.rows) assert.equal(row.result, 'NOT-TESTED');
});

test('a lane whose TAP is garbage collapses (LANE_MALFORMED_OUTPUT), never PASS', () => {
  const lane = laneFor('complete garbage, not TAP at all', 1, 1);
  assert.equal(lane.collapsed, true);
  assert.equal(lane.collapseCode, 'LANE_MALFORMED_OUTPUT');
  for (const row of lane.rows) assert.equal(row.result, 'NOT-TESTED');
});

test('a declared-count mismatch collapses the lane and withholds its PASS rows (LANE_COUNT_MISMATCH)', () => {
  const tap = buildTap([
    { name: 'alpha passes', ok: true },
    { name: 'beta passes', ok: true },
    { name: 'gamma passes', ok: true },
  ]);
  const lane = laneFor(tap, 2, 0); // TAP says 3, manifest says 2 — drift must collapse
  assert.equal(lane.collapsed, true);
  assert.ok(lane.problems.includes('LANE_COUNT_MISMATCH'));
  assert.equal(lane.rows.length, 3);
  for (const row of lane.rows) {
    assert.equal(row.result, 'NOT-TESTED');
    assert.equal(row.reasonCode, 'LANE_COLLAPSE_PASS_WITHHELD');
  }
});

test('a crashed runner (non-zero exit, no row-level failures) collapses (LANE_UNCOLLECTABLE)', () => {
  const tap = buildTap([{ name: 'alpha passes', ok: true }]);
  const lane = laneFor(tap, 1, 7);
  assert.equal(lane.collapsed, true);
  assert.equal(lane.collapseCode, 'LANE_UNCOLLECTABLE');
  for (const row of lane.rows) assert.equal(row.result, 'NOT-TESTED');
});

test('a file-level load failure row collapses the lane and is never PASS', () => {
  const tap = [
    'TAP version 13',
    `not ok 1 - ${SOURCE}`,
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
  const lane = laneFor(tap, 1, 1);
  assert.equal(lane.collapsed, true);
  assert.equal(lane.collapseCode, 'LANE_MALFORMED_OUTPUT');
  for (const row of lane.rows) assert.notEqual(row.result, 'PASS');
});

// ---------------------------------------------------------------------------
// Directives — never certify
// ---------------------------------------------------------------------------

test('a skip directive never certifies: NOT-TESTED with the SKIP code', () => {
  const tap = [
    'TAP version 13',
    'ok 1 - wired behavior passes',
    'not ok 2 - unwired behavior # SKIP not wired in this sandbox',
    '1..2',
    '# tests 2',
    '# pass 1',
    '# fail 0',
    '# cancelled 0',
    '# skipped 1',
    '# todo 0',
  ].join('\n');
  const lane = laneFor(tap, 2, 0);
  assert.equal(lane.collapsed, false);
  const skipped = lane.rows.find((row) => row.requirement.includes('unwired'));
  assert.equal(skipped.result, 'NOT-TESTED');
  assert.equal(skipped.reasonCode, 'SKIP');
});

test('a todo directive never certifies: NOT-TESTED with the TODO code', () => {
  const tap = [
    'TAP version 13',
    'not ok 1 - planned behavior # TODO later stop point',
    '1..1',
    '# tests 1',
    '# pass 0',
    '# fail 0',
    '# cancelled 0',
    '# skipped 0',
    '# todo 1',
  ].join('\n');
  const lane = laneFor(tap, 1, 0);
  assert.equal(lane.collapsed, false);
  assert.equal(lane.rows[0].result, 'NOT-TESTED');
  assert.equal(lane.rows[0].reasonCode, 'TODO');
});

test('a cancelled (timeout) row is NOT-TESTED, never PASS (ROW_CANCELLED)', () => {
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
  const lane = laneFor(tap, 1, 1);
  assert.equal(lane.collapsed, false);
  assert.equal(lane.rows[0].result, 'NOT-TESTED');
  assert.equal(lane.rows[0].reasonCode, 'ROW_CANCELLED');
});

// ---------------------------------------------------------------------------
// Failing rows stay FAIL, visible
// ---------------------------------------------------------------------------

test('a failing row stays FAIL with TEST_FAILED — visible, never buried, never escalated', () => {
  const tap = buildTap([
    { name: 'alpha passes', ok: true },
    { name: 'beta fails', ok: false },
  ]);
  const lane = laneFor(tap, 2, 1);
  assert.equal(lane.collapsed, false);
  assert.equal(lane.rows[0].result, 'PASS');
  assert.equal(lane.rows[1].result, 'FAIL');
  assert.equal(lane.rows[1].reasonCode, 'TEST_FAILED');
});

test('a collapsed lane keeps its genuine FAIL rows FAIL (not withheld, not hidden)', () => {
  const tap = buildTap([
    { name: 'alpha passes', ok: true },
    { name: 'beta fails', ok: false },
  ]);
  const lane = laneFor(tap, 5, 1); // count mismatch triggers collapse
  assert.equal(lane.collapsed, true);
  const alpha = lane.rows.find((row) => row.requirement === 'alpha passes');
  const beta = lane.rows.find((row) => row.requirement === 'beta fails');
  assert.equal(alpha.result, 'NOT-TESTED'); // PASS withheld under collapse
  assert.equal(alpha.reasonCode, 'LANE_COLLAPSE_PASS_WITHHELD');
  assert.equal(beta.result, 'FAIL'); // genuine failure stays visible
  assert.equal(beta.reasonCode, 'TEST_FAILED');
});

// ---------------------------------------------------------------------------
// Malformed rows — never PASS
// ---------------------------------------------------------------------------

test('a row with an unknown field is dropped with ROW_UNKNOWN_FIELD, never PASS', () => {
  const coerced = certify.coerceRow(
    { testId: 't1', category: 'SHARED', requirement: 'r', result: 'PASS', reasonCode: 'TEST_PASSED', payload: 'synthetic-payload-value' },
    SOURCE,
  );
  assert.equal(coerced.row, null);
  assert.equal(coerced.problem, 'ROW_UNKNOWN_FIELD');
});

test('a row with an unknown result value degrades to NOT-TESTED (ROW_UNKNOWN_RESULT)', () => {
  const coerced = certify.coerceRow(
    { testId: 't1', category: 'SHARED', requirement: 'r', result: 'MAYBE', reasonCode: 'TEST_PASSED' },
    SOURCE,
  );
  assert.equal(coerced.problem, 'ROW_UNKNOWN_RESULT');
  assert.equal(coerced.row.result, 'NOT-TESTED');
  assert.equal(coerced.row.reasonCode, 'ROW_UNKNOWN_RESULT');
});

test('a PASS row with no reason code is not understood evidence: NOT-TESTED (ROW_MISSING_REASON_CODE)', () => {
  const coerced = certify.coerceRow(
    { testId: 't1', category: 'SHARED', requirement: 'r', result: 'PASS', reasonCode: null },
    SOURCE,
  );
  assert.equal(coerced.problem, 'ROW_MISSING_REASON_CODE');
  assert.equal(coerced.row.result, 'NOT-TESTED');
});

test('a row with an unsafe (non-UPPER_SNAKE) reason code degrades to NOT-TESTED (ROW_MALFORMED)', () => {
  const coerced = certify.coerceRow(
    { testId: 't1', category: 'SHARED', requirement: 'r', result: 'FAIL', reasonCode: 'leaky message text!!' },
    SOURCE,
  );
  assert.equal(coerced.problem, 'ROW_MALFORMED');
  assert.equal(coerced.row.result, 'NOT-TESTED');
});

test('a row missing its identity (empty testId/category/requirement) is dropped (ROW_MALFORMED)', () => {
  const a = certify.coerceRow({ testId: '', category: 'SHARED', requirement: 'r', result: 'PASS', reasonCode: 'TEST_PASSED' }, SOURCE);
  const b = certify.coerceRow({ testId: 't', category: '', requirement: 'r', result: 'PASS', reasonCode: 'TEST_PASSED' }, SOURCE);
  const c = certify.coerceRow({ testId: 't', category: 'SHARED', requirement: '', result: 'PASS', reasonCode: 'TEST_PASSED' }, SOURCE);
  const d = certify.coerceRow('not an object', SOURCE);
  const e = certify.coerceRow(null, SOURCE);
  const f = certify.coerceRow([1, 2, 3], SOURCE);
  for (const coerced of [a, b, c, d, e, f]) {
    assert.equal(coerced.row, null);
    assert.equal(coerced.problem, 'ROW_MALFORMED');
  }
});

test('an oversized reason code degrades to NOT-TESTED (ROW_MALFORMED)', () => {
  const coerced = certify.coerceRow(
    { testId: 't1', category: 'SHARED', requirement: 'r', result: 'PASS', reasonCode: 'A'.repeat(200) },
    SOURCE,
  );
  assert.equal(coerced.problem, 'ROW_MALFORMED');
  assert.equal(coerced.row.result, 'NOT-TESTED');
});

// ---------------------------------------------------------------------------
// Duplicates and conflicts
// ---------------------------------------------------------------------------

test('identical duplicate rows collapse to one NOT-TESTED row (ROW_DUPLICATE_IDENTICAL), never PASS', () => {
  const row = { testId: 't1', category: 'SHARED', requirement: 'r', result: 'PASS', reasonCode: 'TEST_PASSED', sourceFile: SOURCE };
  const resolved = certify.resolveDuplicates([row, { ...row }]);
  assert.equal(resolved.rows.length, 1);
  assert.equal(resolved.rows[0].result, 'NOT-TESTED');
  assert.equal(resolved.rows[0].reasonCode, 'ROW_DUPLICATE_IDENTICAL');
  assert.equal(resolved.duplicateCount, 1);
});

test('conflicting rows (same testId, different results) collapse to FAIL (ROW_CONFLICTING_EVIDENCE)', () => {
  const rows = [
    { testId: 't1', category: 'SHARED', requirement: 'r', result: 'PASS', reasonCode: 'TEST_PASSED', sourceFile: SOURCE },
    { testId: 't1', category: 'SHARED', requirement: 'r', result: 'FAIL', reasonCode: 'TEST_FAILED', sourceFile: SOURCE },
  ];
  const resolved = certify.resolveDuplicates(rows);
  assert.equal(resolved.rows.length, 1);
  assert.equal(resolved.rows[0].result, 'FAIL');
  assert.equal(resolved.rows[0].reasonCode, 'ROW_CONFLICTING_EVIDENCE');
  assert.equal(resolved.conflictCount, 1);
});

test('conflicting evidence across lanes surfaces as FAIL in the assembled report', () => {
  const rowShape = (result, reasonCode) => ({
    testId: 'shared/tests/dup.test.mjs::same requirement',
    category: 'SHARED',
    requirement: 'same requirement',
    result,
    reasonCode,
    sourceFile: 'shared/tests/dup.test.mjs',
  });
  const laneA = certify.laneFromRows('lane-a', [rowShape('PASS', 'TEST_PASSED')]);
  const laneB = certify.laneFromRows('lane-b', [rowShape('FAIL', 'TEST_FAILED')]);
  const report = certify.assembleReport([
    { lane: laneA, declaredTests: 1 },
    { lane: laneB, declaredTests: 1 },
  ]);
  assert.equal(report.rows.length, 1);
  assert.equal(report.rows[0].result, 'FAIL');
  assert.equal(report.rows[0].reasonCode, 'ROW_CONFLICTING_EVIDENCE');
  assert.equal(report.totals.fail, 1);
  assert.equal(certify.verifyReport(report).ok, true);
});

// ---------------------------------------------------------------------------
// Missing evidence at report level
// ---------------------------------------------------------------------------

test('an empty report (no lanes at all) still verifies — zero rows, zero totals, zero lanes', () => {
  const report = certify.assembleReport([]);
  assert.equal(report.totals.total, 0);
  assert.equal(report.totals.pass, 0);
  assert.equal(report.totals.fail, 0);
  assert.equal(report.totals.notTested, 0);
  assert.equal(certify.verifyReport(report).ok, true);
});

test('a fully-collapsed lane set yields only NOT-TESTED rows and never PASS', () => {
  const collapsed = certify.collapsedInProcessLane('missing-file.test.mjs', 'SHARED', 'LANE_MISSING');
  const undeclared = certify.collapsedInProcessLane('rogue-file.test.mjs', 'UNDECLARED', 'LANE_UNDECLARED');
  const report = certify.assembleReport([
    { lane: collapsed, declaredTests: 3 },
    { lane: undeclared, declaredTests: 0 },
  ]);
  assert.equal(report.totals.pass, 0);
  assert.equal(report.totals.notTested, 2);
  for (const lane of report.lanes) {
    assert.equal(lane.collapsed, true);
    assert.ok(typeof lane.collapseCode === 'string');
  }
  assert.equal(certify.verifyReport(report).ok, true);
});

// ---------------------------------------------------------------------------
// Leak injection — surface labels only
// ---------------------------------------------------------------------------

test('a leak injected into the JSON surface throws the JSON surface label only', () => {
  const forbidden = ['synthetic-secret-value-123456'];
  assert.throws(
    () => certify.assertMetadataOnly('{"leaked":"synthetic-secret-value-123456"}', '<html></html>', forbidden),
    (err) => err.message === 'CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_JSON',
  );
});

test('a leak injected into the HTML surface throws the HTML surface label only', () => {
  const forbidden = ['synthetic-secret-value-123456'];
  assert.throws(
    () => certify.assertMetadataOnly('{}', '<p>synthetic-secret-value-123456</p>', forbidden),
    (err) => err.message === 'CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_HTML',
  );
});

test('the throw never carries the leaked material itself', () => {
  const forbidden = ['synthetic-secret-value-123456'];
  try {
    certify.assertMetadataOnly('{"leaked":"synthetic-secret-value-123456"}', '', forbidden);
    assert.fail('expected a throw');
  } catch (err) {
    assert.equal(err.message, 'CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_JSON');
    assert.ok(!err.message.includes('synthetic-secret'));
    assert.equal(err.stack === undefined, false); // stack exists but the message is the label only
    assert.ok(!err.message.includes('123456'));
  }
});

// ---------------------------------------------------------------------------
// Tamper detection — every mutation the verifier must catch
// ---------------------------------------------------------------------------

function buildReport() {
  const green = certify.collectLane({
    laneId: SOURCE,
    category: 'SHARED',
    tap: buildTap([{ name: 'alpha passes', ok: true }, { name: 'beta passes', ok: true }]),
    declaredTests: 2,
    sourceFiles: [SOURCE],
    runnerExit: 0,
  });
  return certify.assembleReport([{ lane: green, declaredTests: 2 }]);
}

test('the verifier rejects a tampered totals line (TOTALS_PASS_MISMATCH)', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.totals.pass = 5;
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.includes('TOTALS_PASS_MISMATCH'));
});

test('the verifier rejects a forged PASS row appended to the report', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.rows.push({
    testId: 'forged::row', category: 'SHARED', requirement: 'never ran',
    result: 'PASS', reasonCode: 'TEST_PASSED', sourceFile: SOURCE,
  });
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.length > 0); // totals/lanes/categories arithmetic all break
});

test('the verifier rejects a flipped result (PASS -> NOT-TESTED) with broken arithmetic', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.rows[0].result = 'NOT-TESTED';
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.includes('TOTALS_PASS_MISMATCH') || verdict.violations.includes('TOTALS_NOTTESTED_MISMATCH'));
});

test('the verifier rejects a row with an unsafe reason code (ROW_REASON_CODE_UNSAFE)', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.rows[0].reasonCode = 'lowercase with spaces';
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.includes('ROW_REASON_CODE_UNSAFE'));
});

test('the verifier rejects an unknown top-level key (REPORT_UNKNOWN_KEY)', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.secretNote = 'should not be here';
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.includes('REPORT_UNKNOWN_KEY'));
});

test('the verifier rejects an unknown row key (ROW_UNKNOWN_KEY)', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.rows[0].payload = 'synthetic payload content';
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.includes('ROW_UNKNOWN_KEY'));
});

test('the verifier rejects duplicated testIds (ROW_TESTID_DUPLICATE)', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.rows[1].testId = tampered.rows[0].testId;
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.includes('ROW_TESTID_DUPLICATE'));
});

test('the verifier rejects rows that are not canonically sorted (ROWS_NOT_CANONICALLY_SORTED)', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.rows.reverse();
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.includes('ROWS_NOT_CANONICALLY_SORTED'));
});

test('the verifier rejects broken lane arithmetic (LANE_ARITHMETIC_MISMATCH)', () => {
  const report = buildReport();
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.lanes[0].rowCount = 9;
  const verdict = certify.verifyReport(tampered);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.violations.includes('LANE_ARITHMETIC_MISMATCH') || verdict.violations.includes('LANES_VS_ROWS_MISMATCH'));
});

test('the verifier rejects a non-object report (REPORT_NOT_OBJECT)', () => {
  assert.equal(certify.verifyReport(null).ok, false);
  assert.equal(certify.verifyReport('string').ok, false);
  assert.equal(certify.verifyReport([1]).ok, false);
});

// ---------------------------------------------------------------------------
// Never-PASS invariant sweep across the whole engine surface
// ---------------------------------------------------------------------------

test('INVARIANT: no fail-closed path anywhere in the engine yields a PASS row', () => {
  const neverPassRows = [
    // every collapsed lane variant
    certify.collapsedInProcessLane('a', 'SHARED', 'LANE_MISSING').rows,
    certify.collapsedInProcessLane('b', 'SHARED', 'LANE_UNDECLARED').rows,
    certify.collapsedInProcessLane('c', 'SHARED', 'LANE_UNCOLLECTABLE').rows,
    certify.collapsedInProcessLane('d', 'SHARED', 'LANE_COUNT_MISMATCH').rows,
    certify.collapsedInProcessLane('e', 'SHARED', 'LANE_MALFORMED_OUTPUT').rows,
    // every degraded coercion variant
    certify.coerceRow({ testId: 'x', category: 'SHARED', requirement: 'r', result: 'MAYBE', reasonCode: 'C' }, SOURCE).row,
    certify.coerceRow({ testId: 'x', category: 'SHARED', requirement: 'r', result: 'PASS', reasonCode: null }, SOURCE).row,
    certify.coerceRow({ testId: 'x', category: 'SHARED', requirement: 'r', result: 'PASS', reasonCode: 'bad code' }, SOURCE).row,
    // directives and cancellation
    certify.rowForTapOutcome({ directive: 'skip', ok: true, name: 'n', failureType: null, fileLevel: false }, 'SHARED', SOURCE),
    certify.rowForTapOutcome({ directive: 'todo', ok: true, name: 'n', failureType: null, fileLevel: false }, 'SHARED', SOURCE),
    certify.rowForTapOutcome({ directive: 'none', ok: true, name: 'n', failureType: 'testTimeoutFailure', fileLevel: false }, 'SHARED', SOURCE),
    certify.rowForTapOutcome({ directive: 'none', ok: true, name: 'n', failureType: null, fileLevel: true }, 'SHARED', SOURCE),
  ].flat().filter((row) => row !== null);
  for (const row of neverPassRows) {
    assert.notEqual(row.result, 'PASS', `fail-closed path produced PASS: ${JSON.stringify(row)}`);
  }
});
