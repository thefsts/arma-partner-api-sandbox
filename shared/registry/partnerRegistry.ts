// Stop Point 7 — partner registry contract.
//
// The single source of truth for organization -> partner -> entitlement ->
// capability -> status -> API version resolution. Partner logic is NEVER
// hardcoded throughout ARMA; every protected decision resolves through this
// registry and FAILS CLOSED on anything unknown, suspended, revoked,
// expired, or out of the capability's version window.

export type PartnerStatus = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
export type OrgStatus = 'ACTIVE' | 'SUSPENDED';
export type EntitlementStatus = 'ACTIVE' | 'INACTIVE' | 'REVOKED' | 'EXPIRED';
export type BindingStatus = 'ACTIVE' | 'INACTIVE';

export interface CapabilityDefinition {
  readonly capability: string;
  /** Minimum API version this capability implementation accepts. */
  readonly minApiVersion: string;
  /** Maximum API version this capability implementation accepts. */
  readonly maxApiVersion: string;
}

export interface EntitlementDefinition {
  readonly entitlement: string;
  readonly status: EntitlementStatus;
  /** Epoch ms after which the entitlement no longer applies. */
  readonly validUntil?: number;
  readonly capabilities: readonly CapabilityDefinition[];
}

export interface PartnerRecord {
  readonly partnerId: string;
  readonly status: PartnerStatus;
  readonly entitlements: readonly EntitlementDefinition[];
}

export interface OrgRecord {
  readonly orgId: string;
  readonly status: OrgStatus;
  /** Partners this org is bound to. */
  readonly partnerBindings: readonly {
    partnerId: string;
    status: BindingStatus;
    entitlements: readonly string[];
  }[];
}

export type RegistryFailureCode =
  | 'PARTNER_UNKNOWN' | 'PARTNER_SUSPENDED' | 'PARTNER_REVOKED'
  | 'ORG_UNKNOWN' | 'ORG_SUSPENDED' | 'ORG_NOT_BOUND_TO_PARTNER'
  | 'BINDING_UNKNOWN' | 'BINDING_INACTIVE'
  | 'ENTITLEMENT_MISSING' | 'ENTITLEMENT_INACTIVE' | 'ENTITLEMENT_REVOKED' | 'ENTITLEMENT_EXPIRED'
  | 'CAPABILITY_UNKNOWN' | 'CAPABILITY_VERSION_UNSUPPORTED';

export type RegistryResolution =
  | {
      ok: true;
      partnerId: string;
      orgId: string;
      entitlement: string;
      capability: string;
      /** Version window the caller must negotiate within (inclusive). */
      apiVersionWindow: { min: string; max: string };
    }
  | { ok: false; code: RegistryFailureCode };

export interface PartnerRegistryOptions {
  /** Injected clock (ms since epoch) for expiry checks. */
  readonly now?: () => number;
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;

export class PartnerRegistry {
  private readonly partners = new Map<string, PartnerRecord>();
  private readonly orgs = new Map<string, OrgRecord>();
  private readonly now: () => number;

  constructor(options: PartnerRegistryOptions = {}) {
    this.now = options.now ?? Date.now;
  }

  /** Register (or replace) a partner record. Fails closed on malformed input. */
  registerPartner(record: PartnerRecord): void {
    this.assertPartnerRecord(record);
    this.partners.set(record.partnerId, record);
  }

  /** Register (or replace) an organization record. */
  registerOrg(record: OrgRecord): void {
    this.assertOrgRecord(record);
    this.orgs.set(record.orgId, record);
  }

  getPartner(partnerId: string): PartnerRecord | null {
    return this.partners.get(partnerId) ?? null;
  }

  getOrg(orgId: string): OrgRecord | null {
    return this.orgs.get(orgId) ?? null;
  }

  /**
   * Resolve the full authorization chain for a protected operation:
   * org -> binding -> entitlement -> capability -> version window. Every
   * unknown or inactive element fails closed with a typed code.
   */
  resolve(input: { partnerId: string; orgId: string; entitlement: string; capability: string }): RegistryResolution {
    if (!isId(input?.partnerId)) return { ok: false, code: 'PARTNER_UNKNOWN' };
    if (!isId(input?.orgId)) return { ok: false, code: 'ORG_UNKNOWN' };
    const partner = this.partners.get(input.partnerId);
    if (!partner) return { ok: false, code: 'PARTNER_UNKNOWN' };
    if (partner.status === 'SUSPENDED') return { ok: false, code: 'PARTNER_SUSPENDED' };
    if (partner.status === 'REVOKED') return { ok: false, code: 'PARTNER_REVOKED' };

    const org = this.orgs.get(input.orgId);
    if (!org) return { ok: false, code: 'ORG_UNKNOWN' };
    if (org.status === 'SUSPENDED') return { ok: false, code: 'ORG_SUSPENDED' };

    const binding = org.partnerBindings.find((b) => b.partnerId === input.partnerId);
    if (!binding) return { ok: false, code: 'ORG_NOT_BOUND_TO_PARTNER' };
    if (binding.status !== 'ACTIVE') return { ok: false, code: 'BINDING_INACTIVE' };
    if (!binding.entitlements.includes(input.entitlement)) return { ok: false, code: 'BINDING_UNKNOWN' };

    const entitlement = partner.entitlements.find((e) => e.entitlement === input.entitlement);
    if (!entitlement) return { ok: false, code: 'ENTITLEMENT_MISSING' };
    if (entitlement.status === 'INACTIVE') return { ok: false, code: 'ENTITLEMENT_INACTIVE' };
    if (entitlement.status === 'REVOKED') return { ok: false, code: 'ENTITLEMENT_REVOKED' };
    if (entitlement.status === 'EXPIRED') return { ok: false, code: 'ENTITLEMENT_EXPIRED' };
    if (entitlement.validUntil !== undefined && this.now() >= entitlement.validUntil) {
      return { ok: false, code: 'ENTITLEMENT_EXPIRED' };
    }

    const capability = entitlement.capabilities.find((c) => c.capability === input.capability);
    if (!capability) return { ok: false, code: 'CAPABILITY_UNKNOWN' };
    if (!isVersion(capability.minApiVersion) || !isVersion(capability.maxApiVersion)) {
      // A capability with a malformed version window is unusable — fail closed.
      return { ok: false, code: 'CAPABILITY_VERSION_UNSUPPORTED' };
    }
    if (compareVersions(capability.minApiVersion, capability.maxApiVersion) > 0) {
      return { ok: false, code: 'CAPABILITY_VERSION_UNSUPPORTED' };
    }

    return {
      ok: true,
      partnerId: partner.partnerId,
      orgId: org.orgId,
      entitlement: entitlement.entitlement,
      capability: capability.capability,
      apiVersionWindow: { min: capability.minApiVersion, max: capability.maxApiVersion },
    };
  }

  private assertPartnerRecord(record: PartnerRecord): void {
    if (!record || typeof record !== 'object') throw new Error('REGISTRY_PARTNER_RECORD_INVALID');
    if (!isId(record.partnerId)) throw new Error('REGISTRY_PARTNER_ID_INVALID');
    if (record.status !== 'ACTIVE' && record.status !== 'SUSPENDED' && record.status !== 'REVOKED') {
      throw new Error('REGISTRY_PARTNER_STATUS_INVALID');
    }
    if (!Array.isArray(record.entitlements)) throw new Error('REGISTRY_PARTNER_RECORD_INVALID');
    for (const e of record.entitlements) {
      if (!e || typeof e !== 'object' || !isId(e.entitlement)) throw new Error('REGISTRY_ENTITLEMENT_INVALID');
      if (e.status !== 'ACTIVE' && e.status !== 'INACTIVE' && e.status !== 'REVOKED' && e.status !== 'EXPIRED') {
        throw new Error('REGISTRY_ENTITLEMENT_STATUS_INVALID');
      }
      if (e.validUntil !== undefined && (typeof e.validUntil !== 'number' || !Number.isFinite(e.validUntil))) {
        throw new Error('REGISTRY_ENTITLEMENT_INVALID');
      }
      if (!Array.isArray(e.capabilities)) throw new Error('REGISTRY_ENTITLEMENT_INVALID');
      for (const c of e.capabilities) {
        if (!c || typeof c !== 'object' || !isId(c.capability)) throw new Error('REGISTRY_CAPABILITY_INVALID');
        if (!isVersion(c.minApiVersion) || !isVersion(c.maxApiVersion)) {
          throw new Error('REGISTRY_CAPABILITY_VERSION_INVALID');
        }
      }
    }
  }

  private assertOrgRecord(record: OrgRecord): void {
    if (!record || typeof record !== 'object') throw new Error('REGISTRY_ORG_RECORD_INVALID');
    if (!isId(record.orgId)) throw new Error('REGISTRY_ORG_ID_INVALID');
    if (record.status !== 'ACTIVE' && record.status !== 'SUSPENDED') {
      throw new Error('REGISTRY_ORG_STATUS_INVALID');
    }
    if (!Array.isArray(record.partnerBindings)) throw new Error('REGISTRY_ORG_RECORD_INVALID');
    for (const b of record.partnerBindings) {
      if (!b || typeof b !== 'object' || !isId(b.partnerId)) throw new Error('REGISTRY_BINDING_INVALID');
      if (b.status !== 'ACTIVE' && b.status !== 'INACTIVE') throw new Error('REGISTRY_BINDING_STATUS_INVALID');
      if (!Array.isArray(b.entitlements)) throw new Error('REGISTRY_BINDING_INVALID');
      for (const e of b.entitlements) {
        if (typeof e !== 'string' || !e.trim()) throw new Error('REGISTRY_BINDING_INVALID');
      }
    }
  }
}

function isId(value: unknown): value is string {
  return typeof value === 'string' && ID_PATTERN.test(value);
}

const VERSION_RE = /^v[0-9]{1,4}$/;
function isVersion(value: unknown): value is string {
  return typeof value === 'string' && VERSION_RE.test(value);
}

function compareVersions(a: string, b: string): number {
  const na = Number(a.slice(1));
  const nb = Number(b.slice(1));
  return na < nb ? -1 : na > nb ? 1 : 0;
}
