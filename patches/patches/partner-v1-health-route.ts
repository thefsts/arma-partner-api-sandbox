// PATCHES Partner API v1 — live health/readiness route.
//
// HEALTH MUST NOT BE CACHED: this endpoint carries LIVE state (kill-switch
// status, capability availability, clock). The previous `force-static`
// export froze a snapshot at build time, which is WRONG for a health probe
// — a disabled or degraded API would still report "available" from cache.
// The route is therefore fully dynamic: every request computes fresh state.
//
// Note: this module is consumed by the Node reference server test lane
// (patches/tests). The production platform (private PATCHES repo) mounts
// the SAME live-health contract at /api/partner/v1/health via its own
// runtime; porting is a pure wiring change, not a logic change.

import { healthPayloadFor, PARTNER_API_DISABLED_ENV, partnerApiDisabled } from '../lib/server.ts';

export function GET(): Response {
  if (partnerApiDisabled()) {
    // Kill switch: health is live and must reflect the disabled state.
    return Response.json(
      {
        service: 'PATCHES Partner API',
        version: 'v1',
        status: 'disabled',
        directDatabaseAccess: false,
        requiresScopedAuthentication: true,
        at: Date.now(),
      },
      { status: 503, headers: { 'cache-control': 'no-store' } },
    );
  }
  return Response.json(healthPayloadFor(new Date().getTime()), {
    status: 200,
    headers: { 'cache-control': 'no-store' },
  });
}
