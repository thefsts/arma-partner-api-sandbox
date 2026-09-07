// ARMA-side reconciliation for ambiguous Law Shield transfer outcomes (D2).
// OPENED automatically on: PROCESSOR_RECEIPT_MISMATCH, PROCESSOR_TIMEOUT (after
// send), or receipt verification failures with evidence the processor was
// involved. RESOLVED only by an authorized HUMAN resolver (never AI, never
// automatic). The reconciler must record what Law Shield actually reports vs
// what ARMA expected — no silent assumptions about upstream state.
export function openReconciliation(store, { transferId, expectedPayloadHash, expectedDestination, currentArmaState, discrepancyCode, reportedLawShieldState }) {
  const existing = store.getReconciliation(transferId);
  if (existing && existing.resolutionStatus === 'OPEN') return existing; // idempotent reopen
  const record = store.openReconciliation({
    transferId,
    expectedPayloadHash,
    expectedDestination,
    currentArmaState,
    discrepancyCode,
    reportedLawShieldState,
  });
  return record;
}

// Resolve an open reconciliation. AUTHORIZED HUMAN RESOLVER ONLY — mirrors the
// authorizationGuard discipline: directory-resolved human identity, correct
// role, same org. AI/JOY/ROSE can never resolve a Law Shield discrepancy.
export function resolveReconciliation(store, directory, actor, { transferId, resolutionNote, resolutionStatus = 'RESOLVED' }) {
  const userId = actor?.userId;
  if (!userId || typeof userId !== 'string') throw new Error('ACTOR_NOT_AUTHENTICATED');
  const user = directory.getUser(userId);
  if (!user) throw new Error('ACTOR_NOT_AUTHENTICATED');
  if (user.actorType !== 'HUMAN') throw new Error('AI_CANNOT_RESOLVE_RECONCILIATION');
  if (!directory.hasRole(userId, 'LAW_SHIELD_DISCLOSURE_AUTHORIZER')) throw new Error('ACTOR_MISSING_AUTHORIZER_ROLE');

  const transfer = store.getTransfer(transferId);
  if (!transfer) throw new Error('TRANSFER_NOT_FOUND');
  if (!directory.belongsToOrg(userId, transfer.armaOrgId)) throw new Error('ACTOR_NOT_IN_TRANSFER_ORG');

  if (!['RESOLVED', 'QUARANTINED'].includes(resolutionStatus)) throw new Error('INVALID_RESOLUTION_STATUS');
  const note = String(resolutionNote ?? '').trim();
  if (note.length < 10) throw new Error('RESOLUTION_NOTE_TOO_SHORT');

  const record = store.resolveReconciliation(transferId, {
    authorizedResolverUserId: userId,
    resolutionNote: note,
    resolutionStatus,
  });
  return record;
}

// Check whether a transfer may be safely re-sent from reconciliation (only
// after a human confirms the upstream never accepted). Used by transferService
// when a resolver marks RESOLVED and requests re-send: the SAME idempotencyKey
// must be reused so the processor's idempotency registry collapses duplicates.
export function reconciliationReopenApproval(store, transferId) {
  const reconciliation = store.getReconciliation(resolvedTransferIdSafe(transferId));
  if (!reconciliation) return { mayResend: false, reason: 'RECONCILIATION_NOT_FOUND' };
  if (reconciliation.resolutionStatus !== 'RESOLVED') return { mayResend: false, reason: 'RECONCILIATION_STILL_OPEN' };
  return { mayResend: true, reason: 'HUMAN_CONFIRMED_UPSTREAM_NOT_ACCEPTED' };
}

function resolvedTransferIdSafe(transferId) { return transferId; }
