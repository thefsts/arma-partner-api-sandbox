// PATCHES Partner API v1 — tenant scoping, entitlements, capabilities,
// version compatibility. Every operation validates:
//   partner -> organization -> entitlement -> capability -> binding
// The partner principal from authentication is the ONLY source of truth;
// orgId/deviceId/subjectId in a request body are never trusted directly.

import type { SyntheticPartnerStore } from './store.ts';
import { SUPPORTED_API_VERSIONS, type ApiVersion } from './security.ts';

export const MIN_API_VERSION: ApiVersion = 'v1';
export const MAX_API_VERSION: ApiVersion = 'v1';

// Generic contract identifiers ONLY. These are sandbox-contract names and
// carry none of PATCHES' private detection/protection logic.
export const KNOWN_CAPABILITIES = ['traffic_stop_privacy', 'home_privacy'] as const;
export type KnownCapability = (typeof KNOWN_CAPABILITIES)[number];

export type PolicyFailureCode =
  | 'API_VERSION_UNSUPPORTED'
  | 'ORG_UNKNOWN'
  | 'ORG_SUSPENDED'
  | 'ORG_NOT_BOUND_TO_PARTNER'
  | 'ENTITLEMENT_MISSING'
  | 'ENTITLEMENT_INACTIVE'
  | 'ENTITLEMENT_REVOKED'
  | 'ENTITLEMENT_EXPIRED'
  | 'CAPABILITY_UNKNOWN'
  | 'CAPABILITY_VERSION_UNSUPPORTED'
  | 'BINDING_UNKNOWN'
  | 'BINDING_INACTIVE'
  | 'BINDING_ORG_MISMATCH'
  | 'BINDING_CAPABILITY_MISMATCH'
  | 'PARTNER_NOT_CREDENTIAL_OWNER';

export interface PolicyFailure {
  code: PolicyFailureCode;
  detail?: Record<string, unknown>;
}

export function isSupportedApiVersion(version: string): version is ApiVersion {
  return (SUPPORTED_API_VERSIONS as readonly string[]).includes(version);
}

export interface OrgAuthorizationResult {
  ok: boolean;
  failure?: PolicyFailure;
  org?: import('./store.ts').OrganizationRecord;
}

// Step 1: organization must exist, be ACTIVE, and be bound to the
// authenticated partner (organizations.owningPartnerId is the tenant
// boundary — the only way a partner can act on an org).
export function authorizeOrg(store: SyntheticPartnerStore, partnerId: string, orgId: string): OrgAuthorizationResult {
  const org = store.getOrganization(orgId);
  if (!org) return { ok: false, failure: { code: 'ORG_UNKNOWN', detail: { orgId } } };
  if (org.status === 'SUSPENDED') return { ok: false, failure: { code: 'ORG_SUSPENDED', detail: { orgId } } };
  if (org.owningPartnerId !== partnerId) {
    return { ok: false, failure: { code: 'ORG_NOT_BOUND_TO_PARTNER', detail: { orgId, partnerId } } };
  }
  return { ok: true, org };
}

// Step 2: entitlement lookup with full license-window and status checks.
export function checkEntitlement(
  store: SyntheticPartnerStore,
  partnerId: string,
  orgId: string,
  capability: string,
  now: number,
): { ok: boolean; failure?: PolicyFailure } {
  const ent = store.getEntitlement(partnerId, orgId, capability);
  if (!ent) return { ok: false, failure: { code: 'ENTITLEMENT_MISSING', detail: { orgId, capability } } };
  if (ent.status === 'REVOKED') {
    return { ok: false, failure: { code: 'ENTITLEMENT_REVOKED', detail: { orgId, capability, entitlementStatus: ent.status } } };
  }
  if (ent.status === 'INACTIVE') {
    return { ok: false, failure: { code: 'ENTITLEMENT_INACTIVE', detail: { orgId, capability, entitlementStatus: ent.status } } };
  }
  if (now < ent.licensedFrom) {
    return { ok: false, failure: { code: 'ENTITLEMENT_EXPIRED', detail: { orgId, capability, entitlementStatus: ent.status } } };
  }
  if (now > ent.licensedUntil) {
    return { ok: false, failure: { code: 'ENTITLEMENT_EXPIRED', detail: { orgId, capability, entitlementStatus: ent.status } } };
  }
  return { ok: true };
}

// Step 3: capability discovery check — known capability + version window.
export function checkCapability(store: SyntheticPartnerStore, capability: string, apiVersion: string): { ok: boolean; failure?: PolicyFailure } {
  const cap = store.getCapability(capability);
  if (!cap) return { ok: false, failure: { code: 'CAPABILITY_UNKNOWN', detail: { capability } } };
  if (apiVersion !== cap.minApiVersion || apiVersion !== cap.maxApiVersion) {
    return { ok: false, failure: { code: 'CAPABILITY_VERSION_UNSUPPORTED', detail: { capability, apiVersion, minApiVersion: cap.minApiVersion, maxApiVersion: cap.maxApiVersion } } };
  }
  return { ok: true };
}

// Step 4: device/subject binding must exist, be ACTIVE, belong to the org,
// and reference the same capability.
export function checkBinding(store: SyntheticPartnerStore, bindingId: string, orgId: string, capability: string): { ok: boolean; failure?: PolicyFailure } {
  const binding = store.getBinding(bindingId);
  if (!binding) return { ok: false, failure: { code: 'BINDING_UNKNOWN', detail: { bindingId } } };
  if (binding.status === 'INACTIVE') {
    return { ok: false, failure: { code: 'BINDING_INACTIVE', detail: { bindingId, bindingStatus: binding.status } } };
  }
  if (binding.orgId !== orgId) {
    return { ok: false, failure: { code: 'BINDING_ORG_MISMATCH', detail: { bindingId, orgId } } };
  }
  if (binding.capability !== capability) {
    return { ok: false, failure: { code: 'BINDING_CAPABILITY_MISMATCH', detail: { bindingId, capability } } };
  }
  return { ok: true };
}
