// Stop Point 8 — synthetic partner simulators: configuration records.
//
// EVERYTHING in this module is DATA. A simulator identity, a registry
// fixture, a request plan, a fault plan, a delivery script — all plain
// records. No partner behavior is ever a code path: the simulator engine
// (partnerSimulator.ts) and the synthetic contract platform
// (syntheticPlatform.ts) read these records and drive the SHARED Stop
// Point 7 modules. Failure modes (failureModes.ts) are pure record
// transformations: well-behaved base in, faulted scenario config out.
//
// Contract vocabularies (failure-mode categories, evidence surfaces) also
// live here so every other simulators module can depend on this one module
// without cycles.
//
// Synthetic sandbox material ONLY — no private partner identifiers, no
// real credentials, no production data. The secrets below are declared
// synthetic sandbox values; production porting swaps them for the secret
// store (see the SP8 report porting notes).

// ---------------------------------------------------------------------------
// Deterministic clock
// ---------------------------------------------------------------------------

/** Fixed scenario clock start — every run of every scenario begins here. */
export const SCENARIO_CLOCK_START_MS = 1_800_000_000_000;

/** Injectable deterministic clock shared by the simulator and the platform. */
export interface ScenarioClock {
  now(): number;
  advance(ms: number): number;
}

export function makeScenarioClock(startMs: number = SCENARIO_CLOCK_START_MS): ScenarioClock {
  let t = startMs;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
      return t;
    },
  };
}

// ---------------------------------------------------------------------------
// Synthetic secrets (sandbox only — never real credentials)
// ---------------------------------------------------------------------------

export const SYNTHETIC_SIMULATOR_SECRETS = Object.freeze({
  /** Partner request-signing secret (synthetic, sandbox only). */
  signing: 'synthetic-sim-signing-secret-SP8-sandbox',
  /** Platform response-receipt signing secret (synthetic, sandbox only). */
  receipt: 'synthetic-sim-receipt-secret-SP8-sandbox',
  /** Webhook event signing secret (synthetic, sandbox only). */
  webhook: 'synthetic-sim-webhook-secret-SP8-sandbox',
} as const);

/** A secret the fault harness uses to sign WRONGLY (synthetic, sandbox only). */
export const SYNTHETIC_WRONG_SIGNING_SECRET = 'synthetic-sim-wrong-secret-SP8-sandbox';

// ---------------------------------------------------------------------------
// Simulator identities — a simulator is a RECORD, never a code path
// ---------------------------------------------------------------------------

export interface SimulatorIdentity {
  /** Harness identifier of the simulator configuration. */
  readonly simulatorId: string;
  /** Partner this simulator acts as. */
  readonly partnerId: string;
  /** Organization context the simulator's requests claim. */
  readonly orgId: string;
  /** Entitlement the simulator's requests claim. */
  readonly entitlement: string;
  /** Capability the simulator's requests claim. */
  readonly capability: string;
  /** Registry window for the capability (data — the registry enforces it). */
  readonly capabilityMinApiVersion: string;
  readonly capabilityMaxApiVersion: string;
}

/** The well-behaved simulator: happy path through the full SP7 chain. */
export const WELL_BEHAVED_SIMULATOR: SimulatorIdentity = Object.freeze({
  simulatorId: 'sim-well-behaved',
  partnerId: 'partner-sim-alpha',
  orgId: 'org-sim-alpha',
  entitlement: 'partner-sim-basic',
  capability: 'sim-reports-basic',
  capabilityMinApiVersion: 'v1',
  capabilityMaxApiVersion: 'v2',
});

/** A second simulator configured with a different entitlement + capability. */
export const ALTERNATE_ENTITLEMENT_SIMULATOR: SimulatorIdentity = Object.freeze({
  simulatorId: 'sim-alternate-entitlement',
  partnerId: 'partner-sim-beta',
  orgId: 'org-sim-beta',
  entitlement: 'partner-sim-premium',
  capability: 'sim-reports-premium',
  capabilityMinApiVersion: 'v1',
  capabilityMaxApiVersion: 'v2',
});

/** A third simulator sharing an entitlement but exercising another capability. */
export const ALTERNATE_CAPABILITY_SIMULATOR: SimulatorIdentity = Object.freeze({
  simulatorId: 'sim-alternate-capability',
  partnerId: 'partner-sim-gamma',
  orgId: 'org-sim-gamma',
  entitlement: 'partner-sim-basic',
  capability: 'sim-reports-bulk',
  capabilityMinApiVersion: 'v1',
  capabilityMaxApiVersion: 'v3',
});

/** The simulator matrix: every synthetic partner configuration under test. */
export const SYNTHETIC_SIMULATORS: readonly SimulatorIdentity[] = Object.freeze([
  WELL_BEHAVED_SIMULATOR,
  ALTERNATE_ENTITLEMENT_SIMULATOR,
  ALTERNATE_CAPABILITY_SIMULATOR,
]);

// ---------------------------------------------------------------------------
// Registry fixture data (structurally the shared registry records)
// ---------------------------------------------------------------------------

export interface CapabilityData {
  readonly capability: string;
  readonly minApiVersion: string;
  readonly maxApiVersion: string;
}

export interface EntitlementData {
  readonly entitlement: string;
  readonly status: 'ACTIVE' | 'INACTIVE' | 'REVOKED' | 'EXPIRED';
  /** Epoch ms after which the entitlement no longer applies (boundary: now >= validUntil -> expired). */
  readonly validUntil?: number;
  readonly capabilities: readonly CapabilityData[];
}

export interface PartnerRecordData {
  readonly partnerId: string;
  readonly status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  readonly entitlements: readonly EntitlementData[];
}

export interface BindingData {
  readonly partnerId: string;
  readonly status: 'ACTIVE' | 'INACTIVE';
  readonly entitlements: readonly string[];
}

export interface OrgRecordData {
  readonly orgId: string;
  readonly status: 'ACTIVE' | 'SUSPENDED';
  readonly partnerBindings: readonly BindingData[];
}

/** The well-behaved partner record for an identity (ACTIVE, entitled, capable). */
export function wellBehavedPartnerRecord(identity: SimulatorIdentity): PartnerRecordData {
  return {
    partnerId: identity.partnerId,
    status: 'ACTIVE',
    entitlements: [
      {
        entitlement: identity.entitlement,
        status: 'ACTIVE',
        capabilities: [
          {
            capability: identity.capability,
            minApiVersion: identity.capabilityMinApiVersion,
            maxApiVersion: identity.capabilityMaxApiVersion,
          },
        ],
      },
    ],
  };
}

/** The well-behaved org record for an identity (ACTIVE, bound, entitled). */
export function wellBehavedOrgRecord(identity: SimulatorIdentity): OrgRecordData {
  return {
    orgId: identity.orgId,
    status: 'ACTIVE',
    partnerBindings: [
      { partnerId: identity.partnerId, status: 'ACTIVE', entitlements: [identity.entitlement] },
    ],
  };
}

// ---------------------------------------------------------------------------
// Scenario configuration — the single record the whole harness reads
// ---------------------------------------------------------------------------

/** What the simulator asks the platform for (claims the registry decides on). */
export interface ScenarioRequestPlan {
  /** Operation name the platform binds into the receipt (expected-binding field). */
  readonly operation: string;
  readonly method: string;
  readonly path: string;
  /** Raw synthetic payload — signed exactly as provided, never surfaced. */
  readonly payload: string;
  /** Org context the request claims (the registry resolves it). */
  readonly orgId: string;
  /** Entitlement the request claims. */
  readonly entitlement: string;
  /** Capability the request claims. */
  readonly capability: string;
  readonly idempotencyKey: string;
}

/** Client-side fault injection — data the simulator engine applies. */
export interface PartnerFaultPlan {
  /** Corrupt the signature header after signing. */
  readonly tamperSignature?: boolean;
  /** Sign with a secret the platform does not know. */
  readonly wrongSigningSecret?: string;
  /** Sign at now + offset (clock-skew fault when outside ±5 min). */
  readonly timestampOffsetMs?: number;
  /** Present a nonce that violates the nonce pattern. */
  readonly nonceOverride?: string;
  /** Mutate the path after signing (canonical mismatch). */
  readonly tamperPath?: boolean;
  /** Mutate the BODY after signing — the body no longer hashes to the
   *  header's digest (the signature's hash binding fails closed). */
  readonly tamperBody?: boolean;
  /** Present the SAME signed request twice (nonce replay). */
  readonly replayPresentation?: boolean;
  /** Same idempotency key with a DIFFERENT payload (key conflict). */
  readonly idempotencyConflictPresentation?: boolean;
  /** Re-present the SAME payload under the SAME idempotency key with a FRESH
   *  signed request (duplicate collapse — the platform must re-deliver the
   *  recorded SUCCESS outcome, never re-execute, never 4xx/5xx). */
  readonly duplicatePresentation?: boolean;
}

export type ReceiptFault = 'NONE' | 'OMIT' | 'FORGED' | 'TAMPERED' | 'WRONG_OPERATION';

export type DownstreamBehavior = 'HEALTHY' | 'UNAVAILABLE' | 'FAILS_ONCE_THEN_HEALTHY';

/** Circuit-breaker plan: threshold consecutive downstream failures open the circuit. */
export interface CircuitPlan {
  readonly failureThreshold: number;
  readonly resetTimeoutMs: number;
  /** The downstream fails this many times before recovering (canary probes it). */
  readonly downstreamFailures: number;
}

/** Server-side fault injection — data the platform engine applies. */
export interface PlatformFaultPlan {
  /** Kill switch: refuse ALL protected work before any processing. */
  readonly killSwitch?: boolean;
  /** Receipt fault injected into 2xx responses. */
  readonly receiptFault?: ReceiptFault;
  /** Downstream (operation executor) behavior. */
  readonly downstream?: DownstreamBehavior;
  /** Circuit breaker over the downstream (null = no breaker configured). */
  readonly circuit?: CircuitPlan | null;
  /** Event type for the FIRST emitted event (out-of-vocabulary types must fail closed). */
  readonly eventType?: string;
  /** Number of outcome events emitted (default 2: completed + status changed). */
  readonly emitEventCount?: number;
  /** Sequence skip applied to the SECOND emitted event (receiver ordering gap). */
  readonly secondEventSequenceOffset?: number;
}

/** One scripted transport outcome (clean failure, ambiguous failure, or success). */
export type TransportScriptStep =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string; readonly ambiguous?: boolean };

/** Receiver-side fault injection, applied to a captured delivery. */
export interface ReceiverFaultPlan {
  /** Present the SAME signed delivery again (nonce/event replay). */
  readonly rePresentSameDelivery?: boolean;
  /** Present the delivery with a tampered body (signature/hash mismatch). */
  readonly tamperBody?: boolean;
}

/** Webhook delivery script — deterministic, no real network. */
export interface DeliveryPlan {
  /** Transport outcomes in order; the last step repeats when exhausted. */
  readonly transportScript: readonly TransportScriptStep[];
  readonly receiverFaults?: ReceiverFaultPlan;
  /** Re-deliver the first event's envelope (duplicate-collapse contract). */
  readonly deliverTwice?: boolean;
}

/**
 * A complete scenario: identity + world (registry data) + request + client
 * faults + platform faults + delivery script + reconciliation handling.
 * Everything the engines need, as pure data.
 */
export interface ScenarioConfig {
  readonly identity: SimulatorIdentity;
  readonly partnerRecord: PartnerRecordData;
  readonly orgRecord: OrgRecordData;
  readonly request: ScenarioRequestPlan;
  readonly partnerFaults: PartnerFaultPlan;
  readonly platformFaults: PlatformFaultPlan;
  readonly delivery: DeliveryPlan;
  /** Post-ambiguous-delivery reconciliation action. */
  readonly reconcile?: 'RESOLVE' | 'ESCALATE';
  /** World-assembly faults: omit registry records (unknown partner/org). */
  readonly worldFaults?: WorldFaultPlan;
  /** How many times the runner presents the request plan (default 1). */
  readonly presentations?: number;
}

/** Registry-world faults the platform's world assembly applies. */
export interface WorldFaultPlan {
  /** Never register the partner record -> PARTNER_UNKNOWN at resolve time. */
  readonly omitPartnerRecord?: boolean;
  /** Never register the org record -> ORG_UNKNOWN at resolve time. */
  readonly omitOrgRecord?: boolean;
}

/** The well-behaved (control) scenario for an identity — happy path, no faults. */
export function wellBehavedScenario(identity: SimulatorIdentity): ScenarioConfig {
  return {
    identity,
    partnerRecord: wellBehavedPartnerRecord(identity),
    orgRecord: wellBehavedOrgRecord(identity),
    request: {
      operation: 'sim.protected-operation',
      method: 'POST',
      path: '/shared/v1/sim-operations',
      payload: syntheticPayloadFor(identity.simulatorId),
      orgId: identity.orgId,
      entitlement: identity.entitlement,
      capability: identity.capability,
      idempotencyKey: 'sim-op-0001-key',
    },
    partnerFaults: {},
    platformFaults: {
      receiptFault: 'NONE',
      downstream: 'HEALTHY',
      circuit: null,
      eventType: 'processing.completed',
    },
    delivery: { transportScript: [{ ok: true }] },
  };
}

/** Deterministic synthetic payload for a scenario key (never real data). */
export function syntheticPayloadFor(scenarioKey: string): string {
  return JSON.stringify({ syntheticRequest: `sp8-${scenarioKey}` });
}

// ---------------------------------------------------------------------------
// Wire records (what the engines exchange)
// ---------------------------------------------------------------------------

/**
 * Simulator-lane claim headers — the sandbox convention carrying the
 * authorization CLAIMS a request makes (org / entitlement / capability /
 * operation / idempotency key). Claims are inputs the platform resolves
 * through the shared registry: an unknown or inactive claim fails closed
 * with the registry's typed code. The signature binds the request bytes;
 * the registry decides what the claims are worth.
 */
export const SIM_CLAIM_HEADERS = Object.freeze({
  orgId: 'x-shared-org-id',
  entitlement: 'x-shared-entitlement',
  capability: 'x-shared-capability',
  operation: 'x-shared-operation',
  idempotencyKey: 'x-shared-idempotency-key',
} as const);

/** Ordering stream for a simulator's events (partner::org pair). */
export function scenarioStreamFor(identity: SimulatorIdentity): string {
  return `${identity.partnerId}::${identity.orgId}`;
}

/** A platform response as the simulator receives it (raw bytes + headers). */
export interface PlatformResponse {
  readonly status: number;
  readonly rawBody: Buffer;
  readonly headers: Readonly<Record<string, string>>;
}

/** A signed request as the platform receives it (raw bytes + headers). */
export interface PresentableRequest {
  readonly method: string;
  readonly path: string;
  readonly rawBody: Buffer;
  readonly headers: Readonly<Record<string, string>>;
  readonly requestId: string;
  readonly nonce: string;
}

// ---------------------------------------------------------------------------
// Contract vocabularies shared across the simulators modules
// ---------------------------------------------------------------------------

/** The closed set of failure-mode categories (the owner-directed case list). */
export const FAILURE_MODE_CATEGORIES = Object.freeze([
  'SIGNATURE',
  'REPLAY',
  'RECEIPT',
  'AUTHORIZATION',
  'ENTITLEMENT',
  'WEBHOOK',
  'RETRY',
  'RECONCILIATION',
  'CIRCUIT_BREAKER',
  'KILL_SWITCH',
] as const);
export type FailureModeCategory = (typeof FAILURE_MODE_CATEGORIES)[number];

/** Where a failure mode's contract verdict is observed. */
export const EVIDENCE_SURFACES = Object.freeze([
  'PLATFORM_RESPONSE',
  'RECEIPT',
  'DELIVERY',
  'RECEIVER',
  'EMIT',
  'PLAN',
  'SPAN',
  'CIRCUIT',
  'CONTROL',
] as const);
export type EvidenceSurface = (typeof EVIDENCE_SURFACES)[number];
