// Stop Point 7 — shared partner SDK: API version negotiation.
//
// Fail-closed by construction: an unknown version, a malformed version, a
// version outside a capability's supported window, or a MISSING version
// never silently downgrades or upgrades — every case refuses the request.
// Both existing surfaces already follow this discipline (PATCHES route
// scoping + capability windows; Law Shield schema-version exact match);
// the shared SDK makes it one reusable rule.

export const SUPPORTED_SDK_API_VERSIONS = ['v1'] as const;
export type SdkApiVersion = (typeof SUPPORTED_SDK_API_VERSIONS)[number];

export const VERSION_PATTERN = /^v[0-9]{1,4}$/;

export type VersionFailureCode =
  | 'VERSION_UNKNOWN'
  | 'VERSION_MALFORMED'
  | 'VERSION_MISSING'
  | 'VERSION_OUT_OF_CAPABILITY_WINDOW';

export interface VersionNegotiationResult {
  ok: boolean;
  version?: SdkApiVersion;
  supported?: readonly string[];
  failure?: { code: VersionFailureCode; detail?: Record<string, unknown> };
}

/** Is this a structurally valid version token? */
export function isWellFormedVersion(version: unknown): version is string {
  return typeof version === 'string' && VERSION_PATTERN.test(version);
}

/** Is this version in the SDK's supported set (exact match only)? */
export function isSupportedSdkVersion(version: unknown): boolean {
  return isWellFormedVersion(version) && (SUPPORTED_SDK_API_VERSIONS as readonly string[]).includes(version);
}

/** Negotiate: caller-provided version must be well-formed, supported, and
 *  inside the capability's [min, max] window. Every defect fails closed
 *  with a distinct code; the failure detail never carries payloads. */
export function negotiateApiVersion(input: {
  provided?: unknown;
  capabilityMin?: string;
  capabilityMax?: string;
}): VersionNegotiationResult {
  if (input.provided === undefined || input.provided === null || input.provided === '') {
    return { ok: false, supported: SUPPORTED_SDK_API_VERSIONS, failure: { code: 'VERSION_MISSING' } };
  }
  if (!isWellFormedVersion(input.provided)) {
    return { ok: false, supported: SUPPORTED_SDK_API_VERSIONS, failure: { code: 'VERSION_MALFORMED', detail: { provided: input.provided } } };
  }
  if (!isSupportedSdkVersion(input.provided)) {
    return { ok: false, supported: SUPPORTED_SDK_API_VERSIONS, failure: { code: 'VERSION_UNKNOWN', detail: { provided: input.provided } } };
  }
  const version = input.provided as SdkApiVersion;
  if (input.capabilityMin !== undefined || input.capabilityMax !== undefined) {
    const minOk = input.capabilityMin === undefined || compareVersions(input.capabilityMin, version) <= 0;
    const maxOk = input.capabilityMax === undefined || compareVersions(version, input.capabilityMax) <= 0;
    if (!minOk || !maxOk) {
      return {
        ok: false,
        version,
        supported: SUPPORTED_SDK_API_VERSIONS,
        failure: { code: 'VERSION_OUT_OF_CAPABILITY_WINDOW', detail: { provided: version, min: input.capabilityMin, max: input.capabilityMax } },
      };
    }
  }
  return { ok: true, version, supported: SUPPORTED_SDK_API_VERSIONS };
}

/** Numeric compare of vN tokens: v1 < v2 < v10. */
export function compareVersions(a: string, b: string): number {
  const na = Number(a.slice(1));
  const nb = Number(b.slice(1));
  return na < nb ? -1 : na > nb ? 1 : 0;
}
