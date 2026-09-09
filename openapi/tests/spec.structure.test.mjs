// OpenAPI structural validation lane (Stop Point 9).
// Ports /workspace/tmp/validate_spec.py into the repo test matrix so the
// structural rules travel with the repo and run in CI on every push:
//   - OpenAPI 3.1.x document shape, servers, tags, security schemes
//   - every operation: operationId + summary + description + responses
//   - path templates match param names; $refs resolve
//   - schemas: types, required-in-properties, pattern/enum/const usage
//   - response-level $refs resolve into components/responses and are fully
//     validated (headers + content schemas + examples)
//   - examples conform to their schemas
// This file invents nothing: expectations mirror the two published specs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadSpec, resolveRef, validateAgainstSchema, conforms } from './helpers.mjs';

const SPECS = [
  { rel: '../patches-partner-v1.yaml', label: 'PATCHES Partner API v1' },
  { rel: '../../law-shield/openapi/arma-lawshield-v1.yaml', label: 'ARMA Law Shield API v1' },
];

const RESPONSE_KEYS = new Set(['description', 'headers', 'content', 'links']);
const PARAM_KEYS = new Set(['name', 'in', 'required', 'schema', 'description', 'example', 'examples', 'style', 'explode', 'allowEmptyValue', 'deprecated']);
const SCHEMA_KEYWORDS = new Set(['type', 'required', 'properties', 'items', 'enum', 'const', 'pattern', 'description', 'additionalProperties', 'minItems', 'oneOf', 'allOf', 'anyOf', '$ref', 'format', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'title', 'examples', 'default', 'example', 'nullable', 'readOnly', 'writeOnly', 'minProperties', 'maxProperties', 'maxLength', 'minLength', 'uniqueItems', 'not', 'propertyNames', 'deprecated', 'xml', 'externalDocs', 'unevaluatedProperties', 'unevaluatedItems', 'discriminator']);
const METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'trace']);

for (const { rel, label } of SPECS) {
  test(`structure: ${label} — OpenAPI 3.1.x document validates`, () => {
    const doc = loadSpec(rel);
    const errors = [];
    const push = errors.push.bind(errors);

    // --- info ---
    const info = doc.info;
    if (!info || typeof info !== 'object') push('missing info');
    else {
      if (!info.title || typeof info.title !== 'string') push('info.title missing/not string');
      if (!info.version || typeof info.version !== 'string') push('info.version missing/not string');
      if (info.description !== undefined && typeof info.description !== 'string') push('info.description not string');
    }

    // --- openapi version ---
    if (!/^3\.1\.\d+/.test(String(doc.openapi))) push(`openapi version ${doc.openapi} not 3.1.x`);

    // --- servers ---
    const servers = doc.servers;
    if (!Array.isArray(servers) || servers.length === 0) push('servers missing/empty');
    else for (const s of servers) {
      if (!s.url || typeof s.url !== 'string') push('server.url missing');
      if (s.variables !== undefined) {
        for (const [vn, v] of Object.entries(s.variables)) {
          if (v.default === undefined) push(`server variable ${vn} missing default`);
        }
      }
    }

    // --- tags ---
    const tags = new Set((doc.tags ?? []).map((t) => t?.name));
    if ((doc.tags ?? []).some((t) => !t?.name || typeof t.name !== 'string')) push('tag without name');

    // --- security schemes ---
    const schemes = doc.components?.securitySchemes ?? {};
    const schemeNames = new Set(Object.keys(schemes));
    for (const [sn, s] of Object.entries(schemes)) {
      if (!s.type) push(`securityScheme ${sn} missing type`);
      if (s.type === 'apiKey' && !s.name) push(`securityScheme ${sn} (apiKey) missing name`);
      if (s.type === 'apiKey' && !s.in) push(`securityScheme ${sn} (apiKey) missing in`);
      if (s.type === 'http' && !s.scheme) push(`securityScheme ${sn} (http) missing scheme`);
      if (!s.description) push(`securityScheme ${sn} missing description`);
    }

    // --- top-level security ---
    if (doc.security !== undefined) {
      if (!Array.isArray(doc.security)) push('top-level security not array');
      else for (const sec of doc.security) {
        for (const sn of Object.keys(sec ?? {})) if (!schemeNames.has(sn)) push(`top-level security references unknown scheme ${sn}`);
      }
    }

    // --- paths ---
    const paths = doc.paths;
    if (!paths || typeof paths !== 'object') { push('paths missing'); return assert.deepEqual(errors, []); }
    const operationIds = new Set();
    for (const [p, item] of Object.entries(paths)) {
      if (p === 'x-') continue;
      if (!p.startsWith('/')) push(`path ${p} not start-slash`);
      const templateParams = [...p.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
      if (templateParams.length !== new Set(templateParams).size) push(`path ${p} duplicate template params`);
      for (const [method, op] of Object.entries(item)) {
        if (method.startsWith('x-') || method === 'parameters') continue;
        if (!METHODS.has(method)) { push(`unknown method ${method} on ${p}`); continue; }
        const loc = `${method.toUpperCase()} ${p}`;
        if (!op.operationId) push(`${loc}: missing operationId`);
        else {
          if (operationIds.has(op.operationId)) push(`duplicate operationId ${op.operationId}`);
          operationIds.add(op.operationId);
        }
        if (!op.summary || typeof op.summary !== 'string') push(`${loc}: missing summary`);
        if (!op.description || typeof op.description !== 'string') push(`${loc}: missing description`);
        if (!Array.isArray(op.tags) || op.tags.length === 0 || op.tags.some((t) => !tags.has(t))) push(`${loc}: tags missing or undeclared`);
        if (!op.responses || typeof op.responses !== 'object') { push(`${loc}: missing responses`); continue; }
        for (const [code, r] of Object.entries(op.responses)) {
          checkResponse(doc, code, r, `${loc} responses.${code}`, push);
        }
        if (op.security !== undefined) {
          if (!Array.isArray(op.security)) push(`${loc}: security not array`);
          else for (const sec of op.security) {
            for (const sn of Object.keys(sec ?? {})) if (!schemeNames.has(sn)) push(`${loc}: security references unknown scheme ${sn}`);
          }
        }
        if (op.requestBody) checkBody(doc, op.requestBody, `${loc} requestBody`, push);
        if (op.parameters) {
          for (const param of op.parameters) checkParam(doc, param, `${loc} param`, templateParams, push);
        }
        if (typeof op.deprecated !== 'boolean') { /* optional */ }
      }
      // path-level parameters
      if (item.parameters) {
        for (const param of item.parameters) checkParam(doc, param, `${p} path-param`, templateParams, push);
      }
    }

    // --- components/schemas ---
    for (const [sn, s] of Object.entries(doc.components?.schemas ?? {})) {
      checkSchema(doc, s, `components/schemas/${sn}`, push);
    }
    for (const [hn, h] of Object.entries(doc.components?.headers ?? {})) {
      if (!h.description) push(`components/headers/${hn} missing description`);
      if (h.schema) checkSchema(doc, h.schema, `components/headers/${hn}.schema`, push);
      if (h.example !== undefined && h.schema) {
        const errs = conforms(doc, h.schema, h.example);
        for (const e of errs) push(`components/headers/${hn}.example: ${e}`);
      }
    }
    for (const [rn, r] of Object.entries(doc.components?.responses ?? {})) {
      checkResponse(doc, rn, r, `components/responses/${rn}`, push);
    }
    for (const [pn, param] of Object.entries(doc.components?.parameters ?? {})) {
      checkParam(doc, param, `components/parameters/${pn}`, [], push);
    }
    for (const [en, ex] of Object.entries(doc.components?.examples ?? {})) {
      if (ex && typeof ex === 'object' && '$ref' in ex) {
        if (resolveRef(doc, ex.$ref) === null) push(`components/examples/${en}: unresolvable $ref`);
      } else if (ex && typeof ex === 'object' && ex.value === undefined && !ex.externalValue) {
        push(`components/examples/${en} missing value`);
      }
    }

    assert.deepEqual(errors, [], 'structural validation errors');

    function checkResponse(d, code, r, loc, push) {
      if (r && typeof r === 'object' && '$ref' in r) {
        const target = resolveRef(d, r.$ref);
        if (target === null) { push(`${loc}: unresolvable $ref ${r.$ref}`); return; }
        return checkResponse(d, code, target, `${loc} -> ${r.$ref}`, push);
      }
      if (!r || typeof r !== 'object') { push(`${loc}: not a response object`); return; }
      for (const k of Object.keys(r)) if (!RESPONSE_KEYS.has(k) && !k.startsWith('x-')) push(`${loc}: unknown response key ${k}`);
      if (!r.description) push(`${loc}: missing description`);
      if (r.headers) {
        for (const [hn, h] of Object.entries(r.headers)) {
          if (h && typeof h === 'object' && '$ref' in h) {
            if (resolveRef(d, h.$ref) === null) push(`${loc}.headers.${hn}: unresolvable $ref`);
            continue;
          }
          if (!h.description) push(`${loc}.headers.${hn} missing description`);
          if (h.schema) checkSchema(d, h.schema, `${loc}.headers.${hn}.schema`, push);
        }
      }
      if (r.content) {
        for (const [mt, media] of Object.entries(r.content)) {
          if (mt !== 'application/json' && mt !== 'text/plain') push(`${loc}.content: unexpected media type ${mt}`);
          if (media.schema) {
            checkSchema(d, media.schema, `${loc}.content.${mt}.schema`, push);
            const examples = collectExamples(d, media, `${loc}.content.${mt}`, push);
            for (const { name, value } of examples) {
              const errs = conforms(d, media.schema, value);
              for (const e of errs) push(`${loc}.content.${mt} example '${name}': ${e}`);
            }
          }
        }
      }
    }

    function checkBody(d, body, loc, push) {
      if (body.$ref) {
        const target = resolveRef(d, body.$ref);
        if (target === null) { push(`${loc}: unresolvable $ref`); return; }
        return checkBody(d, target, `${loc} -> ${body.$ref}`, push);
      }
      if (!body.description) push(`${loc}: missing description`);
      if (!body.content) { push(`${loc}: missing content`); return; }
      for (const [mt, media] of Object.entries(body.content)) {
        if (media.schema) {
          checkSchema(d, media.schema, `${loc}.content.${mt}.schema`, push);
          const examples = collectExamples(d, media, `${loc}.content.${mt}`, push);
          conformanceLoop: for (const { name, value } of examples) {
            const errs = conforms(d, media.schema, value);
            for (const e of errs) push(`${loc}.content.${mt} example '${name}': ${e}`);
          }
        }
      }
    }

    function collectExamples(d, media, loc, push) {
      const out = [];
      if (media.examples) {
        for (const [name, ex] of Object.entries(media.examples)) {
          if (ex && typeof ex === 'object' && '$ref' in ex) {
            const target = resolveRef(d, ex.$ref);
            if (target === null) { push(`${loc} example '${name}': unresolvable $ref`); continue; }
            out.push({ name, value: target.value });
          } else out.push({ name, value: ex?.value });
        }
      } else if (media.example !== undefined) {
        out.push({ name: 'inline', value: media.example });
      }
      return out;
    }

    function checkParam(d, param, loc, templateParams, push) {
      if (param.$ref) {
        const target = resolveRef(d, param.$ref);
        if (target === null) { push(`${loc}: unresolvable $ref`); return; }
        return checkParam(d, target, `${loc} -> ${param.$ref}`, templateParams, push);
      }
      for (const k of Object.keys(param)) if (!PARAM_KEYS.has(k) && !k.startsWith('x-')) push(`${loc}: unknown param key ${k}`);
      if (!param.name) push(`${loc}: missing name`);
      if (!param.in || !['path', 'query', 'header', 'cookie'].includes(param.in)) push(`${loc}: invalid in`);
      if (param.in === 'path' && param.required !== true) push(`${loc}: path param must be required`);
      if (param.in === 'path' && templateParams.length > 0 && !templateParams.includes(param.name)) push(`${loc}: path param ${param.name} not in template`);
      if (param.schema) checkSchema(d, param.schema, `${loc}.schema`, push);
    }

    function checkSchema(d, s, loc, push) {
      if (s.$ref) {
        if (resolveRef(d, s.$ref) === null) push(`${loc}: unresolvable $ref ${s.$ref}`);
        return;
      }
      if (!s || typeof s !== 'object') { push(`${loc}: not a schema`); return; }
      for (const k of Object.keys(s)) if (!SCHEMA_KEYWORDS.has(k) && !k.startsWith('x-')) push(`${loc}: unknown schema keyword ${k}`);
      if (s.type) {
        const types = Array.isArray(s.type) ? s.type : [s.type];
        for (const t of types) if (!['object', 'array', 'string', 'number', 'integer', 'boolean', 'null'].includes(t)) push(`${loc}: unknown type ${t}`);
      }
      if (s.required && !Array.isArray(s.required)) push(`${loc}: required not array`);
      if (s.required && s.properties) {
        for (const r of s.required) if (!(r in s.properties)) push(`${loc}: required "${r}" not in properties`);
      }
      if (s.enum && !Array.isArray(s.enum)) push(`${loc}: enum not array`);
      if (s.pattern !== undefined && typeof s.pattern !== 'string') push(`${loc}: pattern not string`);
      if (s.properties) for (const [pn, sub] of Object.entries(s.properties)) checkSchema(d, sub, `${loc}.${pn}`, push);
      if (s.items) checkSchema(d, s.items, `${loc}[]`, push);
      if (s.oneOf) s.oneOf.forEach((b, i) => checkSchema(d, b, `${loc}.oneOf[${i}]`, push));
      if (s.allOf) s.allOf.forEach((b, i) => checkSchema(d, b, `${loc}.allOf[${i}]`, push));
      if (s.anyOf) s.anyOf.forEach((b, i) => check(d, s, b, i, push));
      function check(d2, s2, b, i, push2) { checkSchema(d2, b, `${loc}.anyOf[${i}]`, push2); }
    }
  });
}
