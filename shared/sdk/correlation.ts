// Stop Point 7 — shared partner SDK: correlation / request IDs.
//
// One request-ID discipline across every partner integration surface:
//  - ECHO-VALID-OR-GENERATE: an inbound caller-provided ID is echoed only
//    when it is structurally valid (bounded opaque pattern); otherwise a
//    fresh ID is generated and the mismatch is recorded for observability.
//  - CHILD DERIVATION: outbound calls derived from an inbound request
//    carry a derived child ID `${parent}>${suffix}` so a whole call tree
//    can be collapsed to one correlation family without exposing any
//    partner payload content.
//  - PROPAGATION: a fixed header vocabulary (x-request-id,
//    x-correlation-id) so every surface names the correlation IDs the
//    same way.
//
// IDs are opaque synthetic material only — never PII, never payload
// content, and never parsed for meaning.

import { randomUUID } from 'node:crypto';

export const REQUEST_ID_PATTERN = /^req-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const REQUEST_ID_MAX_LENGTH = 128;
export const REQUEST_ID_ECHO_PATTERN = /^[A-Za-z0-9_.:-]{8,128}$/;
export const CHILD_ID_SUFFIX_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
export const CHILD_ID_MAX_DEPTH = 8;

export const REQUEST_ID_HEADER = 'x-request-id';
export const CORRELATION_ID_HEADER = 'x-correlation-id';

export function generateRequestId(): string {
  return `req-${randomUUID()}`;
}

/** Echo an inbound request ID when valid; otherwise generate. Returns both
 *  the effective ID and whether the caller's value was honored. */
export function resolveRequestId(input: { headerValue?: string | string[] | undefined; at: number }): {
  requestId: string;
  echoed: boolean;
  generated: boolean;
} {
  const raw = Array.isArray(input.headerValue) ? input.headerValue[0] : input.headerValue;
  if (typeof raw === 'string' && REQUEST_ID_ECHO_PATTERN.test(raw)) {
    return { requestId: raw, echoed: true, generated: false };
  }
  return { requestId: generateRequestId(), echoed: false, generated: true };
}

/** Derive a child request ID from a parent by appending a scoped suffix:
 *  `req-x` + `retry-1` -> `req-x>retry-1`; a child of that + `send` ->
 *  `req-x>retry-1>send`. The chain is bounded by depth. */
export function deriveChildRequestId(parentId: string, suffix: string): string {
  if (typeof parentId !== 'string' || !parentId) throw new Error('CORRELATION_PARENT_INVALID');
  if (typeof suffix !== 'string' || !CHILD_ID_SUFFIX_PATTERN.test(suffix)) {
    throw new Error('CORRELATION_SUFFIX_INVALID');
  }
  const parts = parentId.split('>');
  if (parts.length >= CHILD_ID_MAX_DEPTH) {
    throw new Error('CORRELATION_DEPTH_EXCEEDED');
  }
  return `${parentId}>${suffix}`;
}
