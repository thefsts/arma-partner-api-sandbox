#!/usr/bin/env node
// Stop Point 10 — the certification report verifier.
//
// Verifies the COMMITTED artifacts at docs/certification/:
//   1. the JSON parses and holds every report invariant (closed key sets,
//      safe reason codes, totals arithmetic rows ↔ totals ↔ lanes ↔
//      categories, canonical ordering, testId uniqueness);
//   2. the HTML regenerates byte-identically from the JSON report — the
//      committed pair cannot drift apart or hide different facts;
//   3. the no-leak sweep passes over BOTH serialized surfaces.
//
// Runs in CI after certify:generate + the lockstep diff. Exits 1 on any
// violation: this is the integrity gate on the owner-readable artifact.
// Violations are reported by CODE and SURFACE only — never content.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');
const tsUrl = (relative) => pathToFileURL(join(repo, relative)).href;

const { assertMetadataOnly, renderReportHtml, verifyReport } = await import(
  tsUrl('certification/certify.ts')
);

const JSON_PATH = join(repo, 'docs', 'certification', 'certification-report.json');
const HTML_PATH = join(repo, 'docs', 'certification', 'certification-report.html');

const violations = [];

const fail = (code) => violations.push(code);

if (!existsSync(JSON_PATH)) fail('ARTIFACT_JSON_MISSING');
if (!existsSync(HTML_PATH)) fail('ARTIFACT_HTML_MISSING');

let jsonText = '';
let htmlText = '';
if (violations.length === 0) {
  jsonText = readFileSync(JSON_PATH, 'utf8');
  htmlText = readFileSync(HTML_PATH, 'utf8');

  // 1. The report object must hold every invariant.
  let report;
  try {
    report = JSON.parse(jsonText);
  } catch {
    fail('ARTIFACT_JSON_UNPARSEABLE');
    report = null;
  }
  if (report !== null) {
    const verdict = verifyReport(report);
    if (!verdict.ok) {
      for (const code of verdict.violations) fail(`REPORT_${code}`);
    }
    // 2. The committed HTML must be the byte-identical rendering of the
    //    committed JSON — no drift, no hidden differences.
    let rendered;
    try {
      rendered = renderReportHtml(report);
    } catch (err) {
      fail('HTML_RENDERING_FAILED');
      rendered = null;
    }
    if (rendered !== null && rendered !== htmlText) {
      fail('HTML_NOT_IN_LOCKSTEP_WITH_JSON');
    }
  }

  // 3. No-leak sweep over both serialized surfaces (synthetic fixtures only).
  try {
    const behaviors = await import(tsUrl('simulators/behaviors.ts'));
    const servers = await import(tsUrl('law-shield/tests/helpers/servers.mjs'));
    const forbidden = [
      ...Object.values(behaviors.SYNTHETIC_SIMULATOR_SECRETS).map(String),
      String(behaviors.SYNTHETIC_WRONG_SIGNING_SECRET),
      ...['SIGNATURE', 'REPLAY', 'RECEIPT', 'AUTHORIZATION', 'ENTITLEMENT', 'WEBHOOK', 'RETRY', 'RECONCILIATION']
        .map((surface) => String(behaviors.syntheticPayloadFor(surface))),
      String(servers.GATEWAY_SECRET),
      String(servers.RECEIPT_SECRET),
      String(servers.PROCESSOR_TOKEN),
    ];
    assertMetadataOnly(jsonText, htmlText, forbidden);
  } catch (err) {
    if (err.message === 'CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_JSON'
      || err.message === 'CERT_SENSITIVE_MATERIAL_DETECTED_REPORT_HTML') {
      fail(err.message);
    } else {
      fail('SWEEP_FIXTURES_UNAVAILABLE');
    }
  }
}

if (violations.length > 0) {
  console.error(`--- certification report VERIFICATION FAILED (${violations.length} violation codes) ---`);
  for (const code of violations) console.error(`  ${code}`);
  process.exit(1);
}

console.log('certification report verification: OK — invariants hold, HTML in lockstep with JSON, no-leak sweep clean.');
process.exit(0);
