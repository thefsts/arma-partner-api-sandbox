// ARMA-side human-only disclosure authorization guard for Law Shield transfers.
// This is THE authoritative gate: NO Law Shield disclosure leaves ARMA unless a
// human with the correct org-scoped role explicitly authorizes it. JOY/ROSE/AI
// can NEVER authorize a Law Shield disclosure — this is the ARMA-side mirror of
// the gateway's AI_CANNOT_AUTHORIZE_TRANSFER rule (defense in depth on both sides).
// The guard stores field NAMES only in policy records (never payload content).

export const LAW_SHIELD_DISCLOSURE_AUTHORIZER_ROLE = 'LAW_SHIELD_DISCLOSURE_AUTHORIZER';

function fail(code, detail) {
  const error = new Error(code);
  error.detail = detail ?? null;
  return error;
}

function requireString(value, code) {
  if (typeof value !== 'string' || !value.trim()) throw fail(code);
  return value;
}

// Check a disclosure authorization attempt. Throws structured error codes on
// ANY rejection (deny-by-default; there is no path that returns approved without
// every check passing). Returns { decision, policyFields } on approval; the
// caller (transferService) then records the durable authorization + audit.
export function checkDisclosureAuthorization(store, directory, actor, request) {
  const userId = actor?.userId;
  if (!userId || typeof userId !== 'string') throw fail('ACTOR_NOT_AUTHENTICATED');

  // 1) Identity must resolve in the authenticated directory (Clerk in prod,
  // synthetic here). Unauthenticated/unknown actors are denied before anything.
  const user = directory.getUser(userId);
  if (!user) throw fail('ACTOR_NOT_AUTHENTICATED');

  // 2) HUMAN-ONLY: AI actors are denied outright regardless of any role claim.
  if (user.actorType !== 'HUMAN') throw fail('AI_CANNOT_AUTHORIZE_TRANSFER');

  // 3) Dedicated role: Law Shield disclosure authorizer (org-scoped).
  if (!directory.hasRole(userId, LAW_SHIELD_DISCLOSURE_AUTHORIZER_ROLE)) {
    throw fail('ACTOR_MISSING_AUTHORIZER_ROLE');
  }

  // 3b) Org scoping: the authorizer must belong to the org that owns the transfer.
  if (!directory.belongsToOrg(userId, request.armaOrgId)) throw fail('ACTOR_NOT_IN_TRANSFER_ORG');

  // 4) Org mapping must exist AND be active in the durable store.
  const orgMapping = store.getOrgMapping(request.armaOrgId);
  if (!orgMapping) throw fail('ORG_MAPPING_MISSING');
  if (!orgMapping.active) throw fail('ORG_MAPPING_INACTIVE');

  // 5) Case mapping: an incident-scoped transfer requires an ACTIVE case
  // mapping to the SAME law shield org (cross-tenant block).
  if (request.incidentId) {
    const caseMapping = store.getCaseMapping(request.armaOrgId, request.incidentId);
    if (!caseMapping) throw fail('CASE_MAPPING_MISSING');
    if (!caseMapping.active) throw fail('CASE_MAPPING_INACTIVE');
    if (caseMapping.lawShieldOrgId !== request.lawShieldOrgId) throw fail('CASE_MAPPING_TENANT_MISMATCH');
  }

  // 6) Reason: required, human-meaningful (>= 10 chars after trim).
  const reason = requireString(request.authorizationReason, 'AUTHORIZATION_REASON_REQUIRED');
  if (reason.trim().length < 10) throw fail('AUTHORIZATION_REASON_TOO_SHORT');

  const policyFields = {
    phiCategories: [...(request.phiCategories ?? [])],
    minimumNecessaryFields: [...(request.minimumNecessaryFields ?? [])],
    redactedFields: [...(request.redactedFields ?? [])],
  };
  return { decision: { approved: true, authorizedByUserId: userId }, policyFields };
}

// Record an APPROVED authorization durably (called by transferService AFTER the
// guard approves). Field names only — never payload content.
export function recordApprovedAuthorization(store, { transferId, armaOrgId, authorizedByUserId, authorizationReason, purposeOfDisclosure, phiCategories, minimumNecessaryFields, redactedFields, auditReference }) {
  return store.recordAuthorization({
    transferId, armaOrgId, authorizedByUserId, authorizationReason,
    purposeOfDisclosure, phiCategories, minimumNecessaryFields, redactedFields,
    policyDecision: 'APPROVED', auditReference,
  });
}

// Deny-by-default helper for AI actors claiming authorizer rights (used in
// tests to prove JOY/ROSE cannot escalate via the ARMA side either).
export function assertNotAiActor(actor) {
  const id = String(actor?.userId ?? '');
  if (id.startsWith('ai-engine-') || id.startsWith('AI:') || ['AI', 'JOY', 'ROSE'].includes(id)) {
    throw fail('AI_CANNOT_AUTHORIZE_TRANSFER');
  }
  return true;
}
