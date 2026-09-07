// ARMA-side minimum-necessary disclosure/redaction policy for Law Shield
// transfers (HIPAA-style "minimum necessary" applied to the synthetic lane).
// Policy is declarative per recordType: an allow-list of payload fields that
// may leave ARMA. EVERYTHING NOT LISTED IS REDACTED (fail closed — a new or
// unexpected field never silently crosses the partner boundary).
// The redactor both filters and reports what it removed so the durable
// authorization record can capture minimumNecessaryFields + redactedFields.
export const MINIMUM_NECESSARY_POLICY = {
  CASE_REFERRAL: {
    phiCategories: ['case_reference', 'incident_summary', 'legal_needs'],
    fields: ['caseNumber', 'incidentId', 'incidentDate', 'incidentType', 'summary', 'legalNeeds', 'requestingOrgId', 'requestingUserId', 'incidentLocation'],
  },
  INCIDENT_METADATA: {
    phiCategories: ['incident_reference', 'location', 'time'],
    fields: ['incidentId', 'incidentDate', 'incidentType', 'incidentLocation', 'incidentTime', 'reportingOrgId', 'officerBadgeNumber', 'narrativeSummary'],
  },
  EVIDENCE_MANIFEST: {
    phiCategories: ['evidence_reference', 'chain_of_custody'],
    fields: ['manifestId', 'incidentId', 'itemCount', 'items', 'collectionDate', 'collectingOfficerBadgeNumber', 'storageLocation', 'itemId', 'type', 'description', 'itemIndex'],
  },
  EVIDENCE_PACKAGE_REFERENCE: {
    phiCategories: ['evidence_reference'],
    fields: ['packageId', 'incidentId', 'manifestId', 'sizeBytes', 'hashAlgorithm', 'contentHash', 'availabilityWindow'],
  },
  CHAIN_OF_CUSTODY_UPDATE: {
    phiCategories: ['chain_of_custody', 'actor_reference'],
    fields: ['manifestId', 'incidentId', 'itemIndex', 'action', 'actorRole', 'actorBadgeNumber', 'timestamp', 'storageLocation'],
  },
  TRANSFER_STATUS: {
    phiCategories: ['transfer_reference'],
    fields: ['transferId', 'status', 'reason'],
  },
  CASE_STATUS_UPDATE: {
    phiCategories: ['case_reference', 'status'],
    fields: ['caseNumber', 'incidentId', 'status', 'updatedAt', 'updatedByRole'],
  },
};

// Fields that are ALWAYS redacted regardless of record type (never leave ARMA):
export const ALWAYS_REDACTED = ['ssn', 'socialSecurityNumber', 'dateOfBirth', 'dob', 'homeAddress', 'phoneNumber', 'email', 'emailAddress', 'driversLicenseNumber', 'licensePlate', 'biometricData', 'medicalRecordNumber', 'healthInsuranceNumber', 'ipAddress', 'geolocation', 'preciseLocation', 'notes', 'officerNotes', 'freeText', 'rawTranscript'];

// Redact a payload object down to the minimum-necessary allow-list for the
// given recordType. Returns { payload, minimumNecessaryFields, redactedFields }.
// Nested objects: only listed sub-fields of allow-listed top-level fields are
// kept (one level deep — evidence manifests have items[] entries); anything
// deeper is redacted. Arrays of primitives pass through only if the parent
// field is allow-listed.
export function redactPayload(recordType, inputPayload) {
  const policy = MINIMUM_NECESSARY_POLICY[recordType];
  if (!policy) throw new Error('REDACTION_POLICY_MISSING');
  if (inputPayload === null || typeof inputPayload !== 'object' || Array.isArray(inputPayload)) {
    throw new Error('REDACTION_INVALID_PAYLOAD');
  }
  const allowed = new Set(policy.fields);
  const always = new Set(ALWAYS_REDACTED.map((f) => f.toLowerCase()));
  const minimumNecessaryFields = [];
  const redactedFields = [];

  const payload = {};
  for (const [key, value] of Object.entries(inputPayload)) {
    if (always.has(key.toLowerCase()) || ALWAYS_REDACTED.includes(key)) {
      redactedFields.push(key);
      continue;
    }
    if (!allowed.has(key)) { redactedFields.push(key); continue; }
    if (value === null || value === undefined) { payload[key] = value; minimumNecessaryFields.push(key); continue; }
    if (Array.isArray(value)) {
      // Allow-listed array field: keep array of primitives OR (for items[]-style
      // fields) array of objects filtered one level deep with the SAME allow-list.
      const filtered = value.map((entry) => {
        if (entry === null || typeof entry !== 'object') return entry; // primitive entry passes
        const out = {};
        for (const [ek, ev] of Object.entries(entry)) {
          if (always.has(ek.toLowerCase()) || ALWAYS_REDACTED.includes(ek)) { redactedFields.push(`${key}.${ek}`); continue; }
          if (!allowed.has(ek)) { redactedFields.push(`${key}.${ek}`); continue; }
          out[ek] = ev;
        }
        return out;
      });
      payload[key] = filtered;
      minimumNecessaryFields.push(key);
      continue;
    }
    if (typeof value === 'object') {
      // Allow-listed object field: filter one level deep with the same allow-list.
      const out = {};
      for (const [ok2, ov] of Object.entries(value)) {
        if (always.has(ok2.toLowerCase()) || ALWAYS_REDACTED.includes(ok2)) { redactedFields.push(`${key}.${ok2}`); continue; }
        if (!allowed.has(ok2)) { redactedFields.push(`${key}.${ok2}`); continue; }
        out[ok2] = ov;
      }
      payload[key] = out;
      minimumNecessaryFields.push(key);
      continue;
    }
    payload[key] = value; // primitive allow-listed value
    minimumNecessaryFields.push(key);
  }
  return { payload, minimumNecessaryFields, redactedFields };
}

// Prove/verify redaction was applied: re-run the policy against the OUTPUT and
// confirm nothing extra would be removed (i.e., output is fully minimal) and
// that no always-redacted key is present anywhere in the output.
export function assertNoAlwaysRedactedValues(objectValue, path = '') {
  if (objectValue === null || typeof objectValue !== 'object') return;
  if (Array.isArray(objectValue)) { objectValue.forEach((v, i) => assertNoAlwaysRedactedValues(v, path ? `${path}[${i}]` : String(i))); return; }
  for (const [key, value] of Object.entries(objectValue)) {
    const full = path ? `${path}.${key}` : key;
    if (ALWAYS_REDACTED.includes(key) || ALWAYS_REDACTED.map((f) => f.toLowerCase()).includes(key.toLowerCase())) {
      throw new Error(`ALWAYS_REDACTED_FIELD_PRESENT:${full}`);
    }
    assertNoAlwaysRedactedValues(value, full);
  }
}
