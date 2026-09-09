// Stop Point 8 — the failure-mode catalog: every failure mode the SP7
// contracts define, exercisable on demand, as PURE DETERMINISTIC
// CONFIGURATION injectors. A mode is a function from the well-behaved
// scenario config to a faulted scenario config — no engine code, no
// partner-specific logic, no hidden state. The engines (partnerSimulator +
// syntheticPlatform) apply whatever the data says, mechanically.
//
// Catalog design (the owner-directed case list, mapped onto the contract
// vocabularies verified from shared/ source):
//
//   SIGNATURE (5)      tampered signature / wrong secret / clock skew /
//                      tampered body (hash binding) / nonce pattern violation
//   REPLAY (3)         same signed bytes twice / duplicate collapse (fresh
//                      signature, same key + same bytes -> recorded-outcome
//                      re-delivery) / idempotency key conflict (same key,
//                      different bytes)
//   RECEIPT (4)        omitted / forged (wrong secret) / tampered content
//                      hash / wrong-operation binding
//   AUTHORIZATION (8)  unknown / suspended / revoked partner, unknown /
//                      suspended org, unbound org, inactive binding,
//                      binding lacking the claimed entitlement
//   ENTITLEMENT (7)    missing (world lacks it) / inactive / revoked /
//                      expiry boundary (now >= validUntil) / claimed-unknown
//                      (binding grants, partner lacks) / unknown capability /
//                      inverted version window (register-valid, resolve
//                      fails CAPABILITY_VERSION_UNSUPPORTED)
//   WEBHOOK (5)        unknown event type (fail-closed build) / event
//                      ordering gap / replayed delivery (nonce burn) /
//                      tampered delivery body / clean-retryable delivery
//                      exhaustion (RETRY_EXHAUSTED dead-letter)
//   RETRY (4)          clean-retryable classification (with same-key
//                      recovery) / ambiguous classification (never blindly
//                      re-sent) / terminal classification / schedule-bound
//                      exhaustion at MAX_RETRY_ATTEMPTS
//   RECONCILIATION (2) ambiguous delivery -> RESOLVE / -> ESCALATE
//   CIRCUIT_BREAKER (1) threshold trip -> OPEN refuses protected work
//   KILL_SWITCH (1)    refuse ALL protected work before any processing
//
// Total: 40 modes across the 10 owner-directed categories. Every mode names
// its category, the evidence surface its verdict is observed on, the
// contract code it must observe (expectedCode), whether the contract
// requires fail-closed rejection (failClosed), and a short metadata-only
// requirement string. All data; nothing else.

import {
  FAILURE_MODE_CATEGORIES,
  SCENARIO_CLOCK_START_MS,
  SYNTHETIC_WRONG_SIGNING_SECRET,
  WELL_BEHAVED_SIMULATOR,
  wellBehavedScenario,
} from './behaviors.ts';
import type {
  EvidenceSurface,
  FailureModeCategory,
  ScenarioConfig,
} from './behaviors.ts';

// ---------------------------------------------------------------------------
// Mode record + injector contract
// ---------------------------------------------------------------------------

/** One failure mode: a pure config injector + its contract expectation. */
export interface FailureMode {
  /** Stable identifier (unique across the catalog). */
  readonly modeId: string;
  readonly category: FailureModeCategory;
  /** Where the contract verdict is observed. */
  readonly surface: EvidenceSurface;
  /** The contract code the scenario must observe. */
  readonly expectedCode: string;
  /** True when the contract requires the faulted surface to fail closed. */
  readonly failClosed: boolean;
  /** What the mode certifies (short, metadata-only). */
  readonly requirement: string;
  /** PURE injector: well-behaved config in, faulted config out. */
  readonly inject: (base: ScenarioConfig) => ScenarioConfig;
}

/** The control (no-fault) mode: the well-behaved baseline itself. */
export interface ControlMode {
  readonly modeId: 'control';
  readonly category: 'CONTROL';
  readonly surface: 'CONTROL';
  readonly expectedCode: 'OPERATION_COMPLETED';
  readonly failClosed: false;
  readonly requirement: string;
}

export const CONTROL_MODE: ControlMode = Object.freeze({
  modeId: 'control',
  category: 'CONTROL',
  surface: 'CONTROL',
  expectedCode: 'OPERATION_COMPLETED',
  failClosed: false,
  requirement: 'well-behaved simulator completes the full SP7 chain '
    + '(sign -> verify -> receipt -> webhook -> receiver)',
});

// ---------------------------------------------------------------------------
// Deterministic injectors — pure data transforms on the scenario config
// ---------------------------------------------------------------------------

/** Flip the partner record status. */
function withPartnerStatus(base: ScenarioConfig, status: 'SUSPENDED' | 'REVOKED'): ScenarioConfig {
  return { ...base, partnerRecord: { ...base.partnerRecord, status } };
}

/** Flip the org record status. */
function withOrgStatus(base: ScenarioConfig, status: 'SUSPENDED'): ScenarioConfig {
  return { ...base, orgRecord: { ...base.orgRecord, status } };
}

/** Replace the org's partner bindings entirely. */
function withBindings(base: ScenarioConfig, partnerBindings: ScenarioConfig['orgRecord']['partnerBindings']): ScenarioConfig {
  return { ...base, orgRecord: { ...base.orgRecord, partnerBindings } };
}

/** Set the claimed-entitlement binding's data. */
function withBinding(base: ScenarioConfig, binding: Partial<ScenarioConfig['orgRecord']['partnerBindings'][number]>): ScenarioConfig {
  return withBindings(base, base.orgRecord.partnerBindings.map((b) =>
    b.partnerId === base.identity.partnerId ? { ...b, ...binding } : b));
}

/** Replace the partner's entitlements data entirely. */
function withEntitlements(
  base: ScenarioConfig,
  entitlements: ScenarioConfig['partnerRecord']['entitlements'],
): ScenarioConfig {
  return { ...base, partnerRecord: { ...base.partnerRecord, entitlements } };
}

/** Map the claimed entitlement's data. */
function withClaimedEntitlementData(
  base: ScenarioConfig,
  transform: (e: ScenarioConfig['partnerRecord']['entitlements'][number]) =>
    ScenarioConfig['partnerRecord']['entitlements'][number],
): ScenarioConfig {
  return withEntitlements(base, base.partnerRecord.entitlements.map((e) =>
    e.entitlement === base.identity.entitlement ? transform(e) : e));
}

/** Ask for a different entitlement claim than the well-behaved default. */
function withClaimedEntitlement(base: ScenarioConfig, entitlement: string): ScenarioConfig {
  return { ...base, request: { ...base.request, entitlement } };
}

/** Ask for a different capability claim than the well-behaved default. */
function withClaimedCapability(base: ScenarioConfig, capability: string): ScenarioConfig {
  return { ...base, request: { ...base.request, capability } };
}

// ---------------------------------------------------------------------------
// The catalog — 40 modes across the 10 owner-directed categories
// ---------------------------------------------------------------------------

const mode = (
  modeId: string,
  category: FailureModeCategory,
  surface: EvidenceSurface,
  expectedCode: string,
  failClosed: boolean,
  requirement: string,
  inject: (base: ScenarioConfig) => ScenarioConfig,
): FailureMode => ({
  modeId, category, surface, expectedCode, failClosed, requirement, inject,
});

export const FAILURE_MODES: readonly FailureMode[] = Object.freeze([

  // --- SIGNATURE (5) ------------------------------------------------------
  mode(
    'signature-tampered-signature',
    'SIGNATURE', 'PLATFORM_RESPONSE', 'SIGNATURE_SIGNATURE_MISMATCH', true,
    'a corrupted signature header is rejected timing-safe, never processed',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, tamperSignature: true } }),
  ),
  mode(
    'signature-wrong-secret',
    'SIGNATURE', 'PLATFORM_RESPONSE', 'SIGNATURE_SIGNATURE_MISMATCH', true,
    'a request signed with a secret the platform does not know is rejected',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, wrongSigningSecret: SYNTHETIC_WRONG_SIGNING_SECRET } }),
  ),
  mode(
    'signature-clock-skew',
    'SIGNATURE', 'PLATFORM_RESPONSE', 'SIGNATURE_CLOCK_SKEW_EXCEEDED', true,
    'a signature outside the ±5 min skew window is rejected before HMAC work',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, timestampOffsetMs: 10 * 60 * 1000 } }),
  ),
  mode(
    'signature-tampered-body',
    'SIGNATURE', 'PLATFORM_RESPONSE', 'SIGNATURE_BODY_HASH_INVALID', true,
    'a body mutated after signing no longer hashes to the signed digest',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, tamperBody: true } }),
  ),
  mode(
    'signature-nonce-pattern-violation',
    'SIGNATURE', 'PLATFORM_RESPONSE', 'SIGNATURE_NONCE_INVALID', true,
    'a nonce violating the nonce pattern is rejected before any processing',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, nonceOverride: 'short' } }),
  ),

  // --- REPLAY (3) ---------------------------------------------------------
  mode(
    'replay-same-signed-request',
    'REPLAY', 'PLATFORM_RESPONSE', 'REQUEST_REPLAYED', true,
    'the same signed request presented twice is refused the second time',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, replayPresentation: true } }),
  ),
  mode(
    'replay-duplicate-collapse',
    'REPLAY', 'PLATFORM_RESPONSE', 'IDEMPOTENCY_DUPLICATE_COLLAPSED', false,
    'same idempotency key + same bytes with a FRESH signature re-delivers the recorded SUCCESS outcome — never an error, never a re-execution',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, duplicatePresentation: true } }),
  ),
  mode(
    'replay-idempotency-conflict',
    'REPLAY', 'PLATFORM_RESPONSE', 'IDEMPOTENCY_KEY_CONFLICT', true,
    'the same idempotency key with DIFFERENT bytes is refused as a conflict',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, idempotencyConflictPresentation: true } }),
  ),

  // --- RECEIPT (4) --------------------------------------------------------
  mode(
    'receipt-omitted',
    'RECEIPT', 'RECEIPT', 'RECEIPT_MISSING_HEADERS', true,
    'a 2xx without receipt headers fails closed on the client',
    (b) => ({ ...b, platformFaults: { ...b.platformFaults, receiptFault: 'OMIT' } }),
  ),
  mode(
    'receipt-forged',
    'RECEIPT', 'RECEIPT', 'RECEIPT_INVALID_SIGNATURE', true,
    'a receipt signed with the wrong secret is rejected by the client',
    (b) => ({ ...b, platformFaults: { ...b.platformFaults, receiptFault: 'FORGED' } }),
  ),
  mode(
    'receipt-tampered-content-hash',
    'RECEIPT', 'RECEIPT', 'RECEIPT_CONTENT_HASH_MISMATCH', true,
    'a signature-valid receipt with a mismatched content hash is rejected',
    (b) => ({ ...b, platformFaults: { ...b.platformFaults, receiptFault: 'TAMPERED' } }),
  ),
  mode(
    'receipt-wrong-operation',
    'RECEIPT', 'RECEIPT', 'RECEIPT_FIELD_MISMATCH', true,
    'a receipt proving the wrong operation fails the expected binding',
    (b) => ({ ...b, platformFaults: { ...b.platformFaults, receiptFault: 'WRONG_OPERATION' } }),
  ),

  // --- AUTHORIZATION (8) --------------------------------------------------
  mode(
    'authorization-partner-unknown',
    'AUTHORIZATION', 'PLATFORM_RESPONSE', 'PARTNER_UNKNOWN', true,
    'an unregistered partner fails closed at resolve time',
    (b) => ({ ...b, worldFaults: { ...b.worldFaults, omitPartnerRecord: true } }),
  ),
  mode(
    'authorization-partner-suspended',
    'AUTHORIZATION', 'PLATFORM_RESPONSE', 'PARTNER_SUSPENDED', true,
    'a suspended partner fails closed before any work',
    (b) => withPartnerStatus(b, 'SUSPENDED'),
  ),
  mode(
    'authorization-partner-revoked',
    'AUTHORIZATION', 'PLATFORM_RESPONSE', 'PARTNER_REVOKED', true,
    'a revoked partner fails closed before any work',
    (b) => withPartnerStatus(b, 'REVOKED'),
  ),
  mode(
    'authorization-org-unknown',
    'AUTHORIZATION', 'PLATFORM_RESPONSE', 'ORG_UNKNOWN', true,
    'an unregistered org fails closed at resolve time',
    (b) => ({ ...b, worldFaults: { ...b.worldFaults, omitOrgRecord: true } }),
  ),
  mode(
    'authorization-org-suspended',
    'AUTHORIZATION', 'PLATFORM_RESPONSE', 'ORG_SUSPENDED', true,
    'a suspended org fails closed before any work',
    (b) => withOrgStatus(b, 'SUSPENDED'),
  ),
  mode(
    'authorization-org-unbound',
    'AUTHORIZATION', 'PLATFORM_RESPONSE', 'ORG_NOT_BOUND_TO_PARTNER', true,
    'an org with no binding to the partner fails closed',
    (b) => withBindings(b, []),
  ),
  mode(
    'authorization-binding-inactive',
    'AUTHORIZATION', 'PLATFORM_RESPONSE', 'BINDING_INACTIVE', true,
    'an inactive binding fails closed (the entitlement is ungranted)',
    (b) => withBinding(b, { status: 'INACTIVE' }),
  ),
  mode(
    'authorization-binding-unknown-entitlement',
    'AUTHORIZATION', 'PLATFORM_RESPONSE', 'BINDING_UNKNOWN', true,
    'a binding lacking the claimed entitlement fails closed',
    (b) => withBinding(b, { entitlements: ['partner-sim-other-entitlement'] }),
  ),

  // --- ENTITLEMENT (7) ----------------------------------------------------
  mode(
    'entitlement-missing',
    'ENTITLEMENT', 'PLATFORM_RESPONSE', 'ENTITLEMENT_MISSING', true,
    'an entitlement the partner record does not carry fails closed',
    (b) => withEntitlements(b, []),
  ),
  mode(
    'entitlement-inactive',
    'ENTITLEMENT', 'PLATFORM_RESPONSE', 'ENTITLEMENT_INACTIVE', true,
    'an inactive entitlement fails closed',
    (b) => withClaimedEntitlementData(b, (e) => ({ ...e, status: 'INACTIVE' })),
  ),
  mode(
    'entitlement-revoked',
    'ENTITLEMENT', 'PLATFORM_RESPONSE', 'ENTITLEMENT_REVOKED', true,
    'a revoked entitlement fails closed',
    (b) => withClaimedEntitlementData(b, (e) => ({ ...e, status: 'REVOKED' })),
  ),
  mode(
    'entitlement-expired-boundary',
    'ENTITLEMENT', 'PLATFORM_RESPONSE', 'ENTITLEMENT_EXPIRED', true,
    'the expiry boundary now() >= validUntil fails closed as EXPIRED',
    (b) => withClaimedEntitlementData(b, (e) => ({ ...e, status: 'ACTIVE', validUntil: SCENARIO_CLOCK_START_MS })),
  ),
  mode(
    'entitlement-claimed-unknown',
    'ENTITLEMENT', 'PLATFORM_RESPONSE', 'ENTITLEMENT_MISSING', true,
    'an entitlement the binding grants but the partner lacks fails closed',
    (b) => ({
      ...withClaimedEntitlement(b, 'partner-sim-claimed-unknown'),
      orgRecord: {
        ...b.orgRecord,
        partnerBindings: b.orgRecord.partnerBindings.map((bind) =>
          bind.partnerId === b.identity.partnerId
            ? { ...bind, entitlements: ['partner-sim-claimed-unknown'] }
            : bind),
      },
    }),
  ),
  mode(
    'entitlement-capability-unknown',
    'ENTITLEMENT', 'PLATFORM_RESPONSE', 'CAPABILITY_UNKNOWN', true,
    'a capability the entitlement does not list fails closed',
    (b) => withClaimedCapability(b, 'sim-reports-unknown'),
  ),
  mode(
    'entitlement-capability-version-inverted',
    'ENTITLEMENT', 'PLATFORM_RESPONSE', 'CAPABILITY_VERSION_UNSUPPORTED', true,
    'an inverted version window (register-valid, resolve-invalid) fails closed',
    (b) => withClaimedEntitlementData(b, (e) => ({
      ...e,
      capabilities: e.capabilities.map((c) =>
        c.capability === b.identity.capability
          ? { ...c, minApiVersion: 'v2', maxApiVersion: 'v1' }
          : c),
    })),
  ),

  // --- WEBHOOK (5) --------------------------------------------------------
  mode(
    'webhook-unknown-event-type',
    'WEBHOOK', 'EMIT', 'WEBHOOK_EVENT_TYPE_UNKNOWN', true,
    'an out-of-vocabulary event type fails closed at build — no event, no delivery',
    (b) => ({ ...b, platformFaults: { ...b.platformFaults, eventType: 'sim.not-an-event' } }),
  ),
  mode(
    'webhook-ordering-gap',
    'WEBHOOK', 'RECEIVER', 'WEBHOOK_ORDERING_GAP', true,
    'an event violating strict per-stream sequence fails closed at the receiver',
    (b) => ({ ...b, platformFaults: { ...b.platformFaults, secondEventSequenceOffset: -1 } }),
  ),
  mode(
    'webhook-replayed-delivery',
    'WEBHOOK', 'RECEIVER', 'WEBHOOK_NONCE_REPLAYED', true,
    're-presenting a delivered event is refused — the nonce is burned',
    (b) => ({ ...b, delivery: { ...b.delivery, receiverFaults: { rePresentSameDelivery: true } } }),
  ),
  mode(
    'webhook-tampered-delivery-body',
    'WEBHOOK', 'RECEIVER', 'WEBHOOK_SIGNATURE_INVALID', true,
    'a delivery with a tampered body fails the signature/hash binding',
    (b) => ({ ...b, delivery: { ...b.delivery, receiverFaults: { tamperBody: true } } }),
  ),
  mode(
    'webhook-delivery-exhaustion',
    'WEBHOOK', 'DELIVERY', 'RETRY_EXHAUSTED', true,
    'a clean-retryable delivery failure exhausts the schedule and dead-letters',
    (b) => ({
      ...b,
      platformFaults: { ...b.platformFaults, emitEventCount: 1 },
      delivery: { ...b.delivery, transportScript: [{ ok: false, code: 'TRANSPORT_ERROR' }] },
    }),
  ),

  // --- RETRY (4) ----------------------------------------------------------
  mode(
    'retry-clean-retryable',
    'RETRY', 'PLAN', 'CLEAN_RETRY', false,
    'a clean-retryable transport failure is safe to re-send under the SAME idempotency key and recovers',
    (b) => ({
      ...b,
      platformFaults: { ...b.platformFaults, downstream: 'FAILS_ONCE_THEN_HEALTHY' },
      presentations: 2,
    }),
  ),
  mode(
    'retry-ambiguous-reconcile',
    'RETRY', 'PLAN', 'AMBIGUOUS_RECONCILE', true,
    'an ambiguous outcome (unverifiable receipt) is never blindly re-sent — it routes to reconciliation',
    (b) => ({ ...b, platformFaults: { ...b.platformFaults, receiptFault: 'OMIT' } }),
  ),
  mode(
    'retry-terminal-classification',
    'RETRY', 'PLAN', 'TERMINAL', true,
    'a terminal failure (bad signature) is never retried',
    (b) => ({ ...b, partnerFaults: { ...b.partnerFaults, tamperSignature: true } }),
  ),
  mode(
    'retry-exhaustion-schedule-bound',
    'RETRY', 'PLAN', 'EXHAUSTED', true,
    'a clean-retryable failure exhausts at the schedule bound (MAX_RETRY_ATTEMPTS) — never retried past it',
    (b) => ({
      ...b,
      platformFaults: { ...b.platformFaults, downstream: 'UNAVAILABLE' },
      presentations: 5,
    }),
  ),

  // --- RECONCILIATION (2) -------------------------------------------------
  mode(
    'reconciliation-resolve',
    'RECONCILIATION', 'SPAN', 'RESOLVED', false,
    'an ambiguous delivery marked PENDING is resolved — reconciliation.completed delivered, span RESOLVED',
    (b) => ({
      ...b,
      delivery: {
        ...b.delivery,
        transportScript: [
          { ok: false, code: 'WEBHOOK_DELIVERY_FAILED', ambiguous: true },
          { ok: true },
        ],
      },
      reconcile: 'RESOLVE',
    }),
  ),
  mode(
    'reconciliation-escalate',
    'RECONCILIATION', 'SPAN', 'REQUIRED_UNRESOLVED', true,
    'an ambiguous delivery marked PENDING escalates — reconciliation.required delivered, span REQUIRED_UNRESOLVED',
    (b) => ({
      ...b,
      delivery: {
        ...b.delivery,
        transportScript: [
          { ok: false, code: 'WEBHOOK_DELIVERY_FAILED', ambiguous: true },
          { ok: true },
        ],
      },
      reconcile: 'ESCALATE',
    }),
  ),

  // --- CIRCUIT_BREAKER (1) ------------------------------------------------
  mode(
    'circuit-threshold-trip-open',
    'CIRCUIT_BREAKER', 'CIRCUIT', 'CIRCUIT_OPEN', true,
    'consecutive downstream failures trip the breaker — OPEN refuses protected work',
    (b) => ({
      ...b,
      platformFaults: {
        ...b.platformFaults,
        circuit: { failureThreshold: 2, resetTimeoutMs: 60_000, downstreamFailures: 3 },
      },
      presentations: 4,
    }),
  ),

  // --- KILL_SWITCH (1) ----------------------------------------------------
  mode(
    'kill-switch-refuses-all',
    'KILL_SWITCH', 'PLATFORM_RESPONSE', 'PLATFORM_KILL_SWITCH', true,
    'the kill switch refuses ALL protected work before any processing',
    (b) => ({ ...b, platformFaults: { ...b.platformFaults, killSwitch: true } }),
  ),
]);

// ---------------------------------------------------------------------------
// Catalog integrity queries (used by the runner + tests)
// ---------------------------------------------------------------------------

/** All mode ids in catalog order. */
export function failureModeIds(): readonly string[] {
  return FAILURE_MODES.map((m) => m.modeId);
}

/** Mode count per category (catalog order). */
export function categoryCounts(): ReadonlyMap<FailureModeCategory, number> {
  const map = new Map<FailureModeCategory, number>();
  for (const m of FAILURE_MODES) {
    map.set(m.category, (map.get(m.category) ?? 0) + 1);
  }
  return map;
}

/** True when every category in the owner-directed list is covered. */
export function categoriesCovered(): boolean {
  const covered = new Set(FAILURE_MODES.map((m) => m.category));
  return FAILURE_MODE_CATEGORIES.every((c) => covered.has(c));
}

/** Modes grouped by category, in catalog order. */
export function modesByCategory(): ReadonlyMap<FailureModeCategory, readonly FailureMode[]> {
  const map = new Map<FailureModeCategory, readonly FailureMode[]>();
  for (const m of FAILURE_MODES) {
    const bucket = map.get(m.category);
    if (bucket) {
      map.set(m.category, [...bucket, m]);
    } else {
      map.set(m.category, [m]);
    }
  }
  for (const [k, v] of map) map.set(k, Object.freeze(v));
  return map;
}

/** Find a mode by id (fails closed: null on unknown). */
export function findFailureMode(modeId: string): FailureMode | null {
  return FAILURE_MODES.find((m) => m.modeId === modeId) ?? null;
}

/**
 * True when the injector is pure: identical input produces identical output
 * (deterministic configuration, no hidden state, no clock or randomness).
 */
export function injectorIsDeterministic(mode: FailureMode): boolean {
  const base = wellBehavedScenario(WELL_BEHAVED_SIMULATOR);
  const a = JSON.stringify(mode.inject(base));
  const b = JSON.stringify(mode.inject(base));
  return a === b;
}

/** Every injector in the catalog is pure (structural sweep). */
export function allInjectorsDeterministic(): boolean {
  return FAILURE_MODES.every((m) => injectorIsDeterministic(m));
}
