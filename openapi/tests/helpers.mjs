// OpenAPI contract-test helpers: spec loading + a small, dependency-free
// JSON-Schema-ish conformance checker covering exactly the schema features
// the two specs use (type, required, properties, enum, const, pattern,
// items, additionalProperties, oneOf, $ref, format, minimum/maximum,
// minItems, readOnly, description — anything else is ignored, not enforced).
//
// The checker is intentionally minimal and dependency-free: the repo runs on
// Node's built-in test runner with zero runtime deps (dev-only `yaml` for
// parsing the specs). Synthetic data only.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve as pathResolve } from 'node:path';
import { parse as parseYaml } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));

// Load + parse an OpenAPI YAML document (OpenAPI 3.1.x).
export function loadSpec(relPath) {
  const text = readFileSync(pathResolve(here, relPath), 'utf8');
  const doc = parseYaml(text);
  if (!doc || typeof doc !== 'object') throw new Error(`spec not a mapping: ${relPath}`);
  if (!String(doc.openapi || '').startsWith('3.1.')) {
    throw new Error(`spec ${relPath} is not OpenAPI 3.1.x (found ${doc.openapi})`);
  }
  return doc;
}

// Resolve a local $ref ('#/components/...') against the spec document.
export function resolveRef(doc, ref) {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) return null;
  let cur = doc;
  for (const seg of ref.slice(2).split('/')) {
    cur = cur?.[decodeURIComponent(seg)];
    if (cur === undefined || cur === null) return null;
  }
  return cur;
}

const TYPE_CHECKS = {
  object: (v) => v !== null && typeof v === 'object' && !Array.isArray(v),
  array: Array.isArray,
  string: (v) => typeof v === 'string',
  number: (v) => typeof v === 'number' && Number.isFinite(v),
  integer: (v) => typeof v === 'number' && Number.isInteger(v),
  boolean: (v) => typeof v === 'boolean',
  null: (v) => v === null,
};

// Validate `value` against `schema`; push human-readable failure strings into
// `errors` (path-prefixed). Follows OpenAPI 3.1 subset semantics:
//   - type may be a string or array of strings (['string','null'])
//   - required fields must be present (undefined ≠ null; null is a value)
//   - enum/const equality is JSON-structural
//   - oneOf: exactly one branch must validate
//   - unresolved / unsupported keywords are ignored (permissive by design —
//     the structural lane (spec.structure.test.mjs) already enforces that the
//     specs only use supported keywords, so this checker stays lean)
export function validateAgainstSchema(doc, schema, value, errors, path) {
  if (schema === null || schema === undefined) return;

  if (schema.$ref) {
    const target = resolveRef(doc, schema.$ref);
    if (target === null) { errors.push(`${path}: unresolvable $ref ${schema.$ref}`); return; }
    return validateAgainstSchema(doc, target, value, errors, path);
  }

  if (schema.oneOf) {
    const branchErrors = schema.oneOf.map((b, i) => {
      const be = [];
      validateAgainstSchema(doc, b, value, be, path);
      return { i, be };
    });
    const ok = branchErrors.filter((b) => b.be.length === 0);
    if (ok.length !== 1) {
      errors.push(`${path}: matched ${ok.length} oneOf branches (need exactly 1)`);
      for (const b of branchErrors) {
        for (const e of b.be) errors.push(`  [branch ${b.i}] ${e}`);
      }
    }
    return;
  }

  if (schema.allOf) {
    for (const b of schema.allOf) validateAgainstSchema(doc, b, value, errors, path);
    // fallthrough: further keywords on the parent still apply
  }

  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const matched = types.some((t) => (TYPE_CHECKS[t] ?? (() => false))(value));
    if (!matched) {
      errors.push(`${path}: expected type ${JSON.stringify(types)} got ${describe(value)}`);
      return;
    }
  }

  if (schema.enum) {
    if (!schema.enum.some((c) => JSON.stringify(c) === JSON.stringify(value))) {
      errors.push(`${path}: ${describe(value)} not in enum ${JSON.stringify(schema.enum)}`);
    }
  }
  if ('const' in schema) {
    if (JSON.stringify(schema.const) !== JSON.stringify(value)) {
      errors.push(`${path}: ${describe(value)} !== const ${JSON.stringify(schema.const)}`);
    }
  }
  if (schema.pattern && typeof value === 'string') {
    if (!new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: ${JSON.stringify(value)} does not match pattern ${schema.pattern}`);
    }
  }
  if (schema.format && typeof value === 'string' && schema.format === 'date-time') {
    if (Number.isNaN(Date.parse(value))) errors.push(`${path}: invalid date-time ${value}`);
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    if (schema.required) {
      for (const r of schema.required) {
        if (!(r in value)) errors.push(`${path}: missing required property "${r}"`);
      }
    }
    if (schema.properties) {
      for (const [k, sub] of Object.entries(schema.properties)) {
        if (k in value) validateAgainstSchema(doc, sub, value[k], errors, `${path}.${k}`);
      }
    }
    if (schema.additionalProperties === false) {
      for (const k of Object.keys(value)) {
        if (!(k in (schema.properties ?? {}))) errors.push(`${path}: unexpected property "${k}" (additionalProperties: false)`);
      }
    }
    if (schema.minProperties !== undefined && Object.keys(value).length < schema.minProperties) {
      errors.push(`${path}: fewer than ${schema.minProperties} properties`);
    }
  }

  if (Array.isArray(value)) {
    if (schema.items) {
      value.forEach((el, i) => validateAgainstSchema(doc, schema.items, el, errors, `${path}[${i}]`));
    }
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${path}: fewer than ${schema.minItems} items`);
    }
  }

  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: ${value} < minimum ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path}: ${value} > maximum ${schema.maximum}`);
  }
}

function describe(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

// Convenience: validate and return the errors array (empty = conforms).
export function conforms(doc, schema, value) {
  const errors = [];
  validateAgainstSchema(doc, schema, value, errors, '$');
  return errors;
}

// Extract every ALL_CAPS code-like token from a text (used by the
// cross-check lane to compare spec tokens against implementation tokens).
export function allCapsTokens(text) {
  const found = new Set();
  const rx = /`?([A-Z][A-Z0-9_]{4,})`?/g;
  let m;
  while ((m = rx.exec(text)) !== null) {
    if (m[1].length >= 6 && m[1].includes('_')) found.add(m[1]);
  }
  return found;
}
