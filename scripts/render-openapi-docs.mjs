#!/usr/bin/env node
// Static OpenAPI documentation renderer (Stop Point 9).
//
// Renders BOTH OpenAPI 3.1.x documents (PATCHES Partner API v1 + ARMA Law
// Shield API v1) to self-contained static HTML pages under docs/openapi/ —
// NO external rendering service, NO network access at render or view time.
// Every page is a single self-contained HTML file (inline CSS + JS-free
// content) that renders correctly from the local file system and from the
// repo's static docs hosting.
//
// Usage: node scripts/render-openapi-docs.mjs   (or: pnpm run render:openapi-docs)
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const OUT_DIR = resolve(root, 'docs/openapi');
mkdirSync(OUT_DIR, { recursive: true });

const SPECS = [
  {
    file: 'openapi/patches-partner-v1.yaml',
    out: 'patches-partner-v1.html',
    title: 'PATCHES Partner API v1 — OpenAPI 3.1 Contract',
    accent: '#1f6feb',
    api: 'PATCHES Partner API',
  },
  {
    file: 'law-shield/openapi/arma-lawshield-v1.yaml',
    out: 'arma-lawshield-v1.html',
    title: 'ARMA Law Shield API v1 — OpenAPI 3.1 Contract',
    accent: '#8250df',
    api: 'ARMA Law Shield API',
  },
];

const esc = (s) => String(s ?? '')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#39;');

function escId(s) { return String(s).replace(/[^a-zA-Z0-9_-]/g, '-'); }

function renderDescription(text) {
  if (!text) return '';
  const lines = String(text).split('\n');
  return lines.map((l) => (l.trim() === '' ? '' : `<p>${esc(l)}</p>`)).join('');
}

function schemaRefName(ref) {
  const m = /#\/components\/schemas\/(.+)$/.exec(ref ?? '');
  return m ? m[1] : String(ref);
}

function renderSchemaNode(node, doc, opts = {}) {
  if (!node) return '<span class="t-unknown">?</span>';
  if (node.$ref) {
    return `<a class="t-ref" href="#schema-${escId(schemaRefName(node.$ref))}">${esc(schemaRefName(node.$ref))}</a>`;
  }
  let out = '';
  const type = node.type;
  if (type === 'array' || (Array.isArray(type) && type.includes('array'))) {
    const inner = renderSchemaNode(node.items, doc);
    out = `<span class="t-array">array&lt;${inner}&gt;</span>`;
    if (node.minItems !== undefined) out += ` <span class="t-meta">(minItems ${node.minItems})</span>`;
  } else if (type === 'object' || (Array.isArray(type) && type.includes('object'))) {
    out = '<span class="t-object">object</span>';
  } else if (Array.isArray(type)) {
    out = `<span class="t-union">${type.map((t) => esc(t)).join(' | ')}</span>`;
  } else if (type) {
    out = `<span class="t-${esc(type)}">${esc(type)}</span>`;
  }
  if (node.enum) out += ` <span class="t-meta">enum: ${node.enum.map((v) => esc(JSON.stringify(v))).join(' | ')}</span>`;
  if (node.const !== undefined) out += ` <span class="t-meta">const: ${esc(JSON.stringify(node.const))}</span>`;
  if (node.pattern) out += ` <span class="t-meta">pattern: ${esc(node.pattern)}</span>`;
  if (node.format) out += ` <span class="t-meta">format: ${esc(node.format)}</span>`;
  if (node.minLength !== undefined) out += ` <span class="t-meta">minLength ${node.minLength}</span>`;
  if (node.maxLength !== undefined) out += ` <span class="t-meta">maxLength ${node.maxLength}</span>`;
  if (node.minimum !== undefined) out += ` <span class="t-meta">min ${node.minimum}</span>`;
  if (node.maximum !== undefined) out += ` <span class="t-meta">max ${node.maximum}</span>`;
  if (node.oneOf) out += ` <span class="t-meta">oneOf [ ${node.oneOf.map((s) => renderSchemaNode(s, doc)).join(' , ')} ]</span>`;
  if (node.allOf) out += ` <span class="t-meta">allOf [ ${node.allOf.map((s) => renderSchemaNode(s, doc)).join(' , ')} ]</span>`;
  if (node.additionalProperties === false) out += ' <span class="t-meta">(closed)</span>';
  if (node.additionalProperties === true) out += ' <span class="t-meta">(free-form)</span>';
  if (opts.brief && !node.$ref) return out;
  return out;
}

function renderExample(value) {
  if (value === undefined || value === null) return '';
  return `<pre class="example"><code>${esc(JSON.stringify(value, null, 2))}</code></pre>`;
}

function renderParameters(op, doc) {
  const params = op.parameters ?? [];
  if (!params.length) return '';
  const rows = params.map((p) => {
    const spec = p.$ref ? resolveRef(doc, p.$ref) : p;
    const name = p.$ref ? refParamName(doc, p.$ref) : p.name;
    const where = esc(spec.in);
    const required = spec.required ? '<span class="req">required</span>' : '<span class="opt">optional</span>';
    const typeHtml = renderSchemaNode(spec.schema, doc, { brief: true });
    const desc = renderDescription(spec.description).replace(/^<p>|<\/p>$/g, '');
    return `<tr><td class="mono">${esc(name)}</td><td>${where}</td><td>${typeHtml}</td><td>${required}</td><td>${desc}</td></tr>`;
  }).join('');
  return `<h4>Parameters</h4><table class="tbl"><thead><tr><th>Name</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function refParamName(doc, ref) {
  const m = /#\/components\/parameters\/(.+)$/.exec(ref);
  return m ? m[1] : ref;
}

function resolveRef(doc, ref) {
  const m = /^#\/(.+)$/.exec(ref);
  if (!m) return {};
  let node = doc;
  for (const part of m[1].split('/')) node = node?.[part];
  return node ?? {};
}

function renderResponses(op, doc) {
  const entries = Object.entries(op.responses ?? {});
  if (!entries.length) return '';
  const blocks = entries.map(([code, resp]) => {
    const r = resp.$ref ? resolveRef(doc, resp.$ref) : resp;
    const desc = renderDescription(r.description);
    let media = '';
    const json = r.content?.['application/json'];
    if (json) {
      const schemaHtml = renderSchemaNode(json.schema, doc);
      media += `<div class="resp-media"><span class="lbl">application/json</span> ${schemaHtml}</div>`;
      const exNames = Object.entries(json.examples ?? {});
      for (const [name, ex] of exNames) {
        const v = ex.$ref ? (resolveRef(doc, ex.$ref).value ?? undefined) : ex.value;
        media += `<details class="ex"><summary>example: ${esc(name)}</summary>${renderExample(v)}</details>`;
      }
      if (json.example !== undefined) {
        media += `<details class="ex"><summary>example</summary>${renderExample(json.example)}</details>`;
      }
    }
    const hdrEntries = Object.entries(r.headers ?? {});
    let hdrs = '';
    if (hdrEntries.length) {
      const rows = hdrEntries.map(([name, h]) => {
        const spec = h.$ref ? resolveRef(doc, h.$ref) : h;
        const typeHtml = renderSchemaNode(spec.schema, doc, { brief: true });
        return `<tr><td class="mono">${esc(name)}</td><td>${typeHtml}</td><td>${esc(spec.description ?? '')}</td></tr>`;
      }).join('');
      hdrs = `<table class="tbl hdr-tbl"><thead><tr><th>Header</th><th>Type</th><th>Description</th></tr></thead><tbody>${rows}</tbody></table>`;
    }
    return `<div class="resp"><div class="resp-code code-${esc(code)}">${esc(code)}</div><div class="resp-body">${desc}${hdrs}${media}</div></div>`;
  }).join('');
  return `<h4>Responses</h4>${blocks}`;
}

function renderSecurity(op, doc) {
  const sec = op.security;
  const globalSec = doc.security;
  const eff = sec ?? globalSec;
  if (!eff || (Array.isArray(eff) && eff.length === 0)) {
    return '<div class="sec-badge unauth">unauthenticated</div>';
  }
  return eff.map((s) => {
    const name = Object.keys(s)[0];
    return `<div class="sec-badge">${esc(name)}</div>`;
  }).join(' ');
}

function renderOperation(method, op, doc, path) {
  const opId = esc(op.operationId ?? '');
  const summary = esc(op.summary ?? '');
  const desc = renderDescription(op.description);
  const tags = (op.tags ?? []).map((t) => `<span class="tag">${esc(t)}</span>`).join(' ');
  let body = '';
  const rb = op.requestBody;
  if (rb) {
    const json = rb.content?.['application/json'];
    if (json) {
      const schemaHtml = renderSchemaNode(json.schema, doc);
      body = `<h4>Request Body ${rb.required ? '<span class="req">required</span>' : '<span class="opt">optional</span>'}</h4><div class="resp-media"><span class="lbl">application/json</span> ${schemaHtml}</div>`;
    }
  }
  return `<div class="op" id="op-${escId(method + path)}">
  <div class="op-head"><span class="method m-${method}">${method.toUpperCase()}</span><span class="op-path mono">${esc(path)}</span>${renderSecurity(op, doc)}</div>
  <div class="op-title"><code class="mono opid">${opId}</code> — ${summary} ${tags}</div>
  ${desc}
  ${renderParameters(op, doc)}
  ${body}
  ${renderResponses(op, doc)}
</div>`;
}

function renderSchemas(doc) {
  const schemas = Object.entries(doc.components?.schemas ?? {});
  if (!schemas.length) return '';
  const blocks = schemas.map(([name, s]) => {
    const props = Object.entries(s.properties ?? {});
    const required = new Set(s.required ?? []);
    let propsHtml = '';
    if (props.length) {
      const rows = props.map(([pname, p]) => {
        const req = required.has(pname) ? '<span class="req">required</span>' : '<span class="opt">optional</span>';
        const typeHtml = renderSchemaNode(p, doc);
        const desc = renderDescription(p.description).replace(/^<p>|<\/p>$/g, '');
        return `<tr><td class="mono">${esc(pname)}</td><td>${req}</td><td>${typeHtml}</td><td>${desc}</td></tr>`;
      }).join('');
      propsHtml = `<table class="tbl"><thead><tr><th>Field</th><th>Required</th><th>Type</th><th>Description</th></tr></thead><tbody>${rows}</tbody></table>`;
    }
    return `<div class="schema" id="schema-${escId(name)}"><h3 class="schema-name">${esc(name)}</h3>${renderDescription(s.description)}${propsHtml}</div>`;
  }).join('');
  return `<h2>Schemas</h2>${blocks}`;
}

function renderHeaders(doc) {
  const headers = Object.entries(doc.components?.headers ?? {});
  if (!headers.length) return '';
  const rows = headers.map(([name, h]) => {
    const spec = h.$ref ? resolveRef(doc, h.$ref) : h;
    const typeHtml = renderSchemaNode(spec.schema, doc, { brief: true });
    return `<tr><td class="mono">${esc(name)}</td><td>${typeHtml}</td><td>${esc(spec.description ?? '')}</td></tr>`;
  }).join('');
  return `<h2>Response Headers</h2><table class="tbl"><thead><tr><th>Header</th><th>Type</th><th>Description</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderSecuritySchemes(doc) {
  const schemes = Object.entries(doc.components?.securitySchemes ?? {});
  if (!schemes.length) return '';
  const blocks = schemes.map(([name, s]) => {
    return `<div class="scheme"><h3 class="schema-name">${esc(name)}</h3><div class="kv"><span class="lbl">type</span> ${esc(s.type)}</div>${s.description ? renderDescription(s.description) : ''}${s.name ? `<div class="kv"><span class="lbl">header</span> <code class="mono">${esc(s.name)}</code></div>` : ''}${s.scheme ? `<div class="kv"><span class="lbl">scheme</span> ${esc(s.scheme)}</div>` : ''}</div>`;
  }).join('');
  return `<h2>Security Schemes</h2>${blocks}`;
}

const CSS = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; color: #1f2328; background: #fff; line-height: 1.55; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 24px 20px 80px; }
a { color: #0969da; text-decoration: none; } a:hover { text-decoration: underline; }
header.hero { border-bottom: 4px solid var(--accent); padding-bottom: 18px; margin-bottom: 28px; }
header.hero h1 { font-size: 26px; margin: 0 0 6px; }
header.hero .meta { color: #57606a; font-size: 14px; }
header.hero .meta span { margin-right: 18px; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; color: #fff; background: var(--accent); }
.info { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 8px; padding: 14px 18px; margin: 18px 0; }
.info p { margin: 6px 0; }
h2 { font-size: 20px; margin: 34px 0 10px; border-bottom: 1px solid #d8dee4; padding-bottom: 6px; }
h3.schema-name { font-size: 16px; margin: 0 0 8px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
h4 { font-size: 13px; margin: 18px 0 6px; text-transform: uppercase; letter-spacing: .04em; color: #57606a; }
.op { border: 1px solid #d0d7de; border-radius: 8px; padding: 14px 18px; margin: 14px 0; }
.op-head { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.method { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 700; font-size: 13px; padding: 2px 8px; border-radius: 5px; color: #fff; }
.m-get { background: #1a7f37; } .m-post { background: #8250df; } .m-put { background: #bf8700; } .m-patch { background: #bf8700; } .m-delete { background: #cf222e; }
.op-path { font-size: 15px; font-weight: 600; }
.op-title { margin: 8px 0 4px; font-size: 15px; }
.opid { font-size: 13px; background: #f6f8fa; padding: 1px 6px; border-radius: 4px; }
.tag { display: inline-block; background: #ddf4ff; color: #0969da; border-radius: 999px; font-size: 11px; padding: 1px 8px; font-weight: 600; margin-left: 4px; }
.sec-badge { font-size: 11px; padding: 2px 8px; border-radius: 4px; background: #fff8c5; border: 1px solid #d4a72c; font-weight: 600; }
.sec-badge.unauth { background: #dafbe1; border-color: #2da44e; }
.tbl { width: 100%; border-collapse: collapse; margin: 8px 0 4px; font-size: 13px; }
.tbl th { text-align: left; background: #f6f8fa; border: 1px solid #d8dee4; padding: 6px 10px; }
.tbl td { border: 1px solid #eaeef2; padding: 6px 10px; vertical-align: top; }
.mono, code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; }
.req { color: #cf222e; font-weight: 700; font-size: 11px; }
.opt { color: #57606a; font-size: 11px; }
.resp { display: flex; gap: 12px; margin: 8px 0; }
.resp-code { font-family: ui-monospace, monospace; font-weight: 700; padding: 2px 10px; border-radius: 5px; color: #fff; min-width: 46px; text-align: center; font-size: 13px; height: fit-content; }
.code-2 { background: #1a7f37; } .code-4 { background: #bf8700; } .code-5 { background: #cf222e; } .code-default { background: #57606a; }
.resp-body { flex: 1; }
.resp-body p { margin: 2px 0; }
.resp-media { margin: 6px 0; font-size: 13px; }
.lbl { display: inline-block; background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 4px; padding: 0 6px; font-size: 11px; font-family: ui-monospace, monospace; }
.t-ref { color: #8250df; font-weight: 600; } .t-array { color: #0550ae; } .t-object { color: #0550ae; } .t-string { color: #0a3069; } .t-number, .t-integer { color: #953800; } .t-boolean { color: #116329; } .t-union { color: #57606a; }
.t-meta { color: #57606a; font-size: 11.5px; }
.example { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 10px 12px; overflow-x: auto; font-size: 12px; margin: 6px 0; max-width: 100%; }
details.ex summary { cursor: pointer; font-size: 12px; color: #0969da; margin: 4px 0; }
.schema { border: 1px solid #d0d7de; border-radius: 8px; padding: 12px 16px; margin: 12px 0; }
.kv { margin: 3px 0; font-size: 13px; }
nav.toc { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px 18px; margin: 18px 0; }
nav.toc b { font-size: 13px; }
nav.toc ul { margin: 6px 0 2px; padding-left: 20px; font-size: 13px; }
nav.toc li { margin: 2px 0; }
footer { border-top: 1px solid #d8dee4; margin-top: 50px; padding-top: 14px; color: #57606a; font-size: 12px; }
`;

function renderToc(doc) {
  const paths = Object.entries(doc.paths ?? {});
  const items = paths.flatMap(([path, item]) => {
    const methods = ['get', 'post', 'put', 'patch', 'delete'].filter((m) => item[m]);
    return methods.map((m) => {
      const op = item[m];
      return `<li><a href="#op-${escId(m + path)}"><span class="method m-${m}" style="font-size:10px">${m.toUpperCase()}</span> ${esc(path)} — ${esc(op.operationId ?? '')}</a></li>`;
    });
  }).join('');
  return `<nav class="toc"><b>Operations</b><ul>${items}</ul></nav>`;
}

function renderOne(spec) {
  const doc = parse(readFileSync(resolve(root, spec.file), 'utf8'));
  const info = doc.info ?? {};
  const servers = (doc.servers ?? []).map((s) => {
    const vars = Object.entries(s.variables ?? {}).map(([k, v]) => `${esc(k)}=${esc(v.default ?? '')}`).join(', ');
    return `<div class="kv"><span class="lbl">server</span> <code class="mono">${esc(s.url)}</code>${vars ? ` <span class="t-meta">(${vars})</span>` : ''}</div>`;
  }).join('');
  const paths = Object.entries(doc.paths ?? {});
  const opsHtml = paths.flatMap(([path, item]) => {
    return ['get', 'post', 'put', 'patch', 'delete']
      .filter((m) => item[m])
      .map((m) => renderOperation(m, item[m], doc, path));
  }).join('');
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(spec.title)}</title>
<style>:root { --accent: ${spec.accent}; }${CSS}</style>
</head>
<body>
<div class="wrap">
<header class="hero">
  <h1>${esc(spec.title)}</h1>
  <div class="meta">
    <span class="pill">OpenAPI ${esc(doc.openapi)}</span>
    <span><b>${esc(info.title ?? spec.api)}</b> <span class="mono">v${esc(info.version ?? '')}</span></span>
    <span>License: ${esc(info.license?.name ?? 'n/a')}</span>
  </div>
  ${servers}
</header>
<div class="info">
  <p><b>Description</b></p>
  ${renderDescription(info.description)}
</div>
${renderToc(doc)}
<h2>Paths</h2>
${opsHtml}
${renderSecuritySchemes(doc)}
${renderHeaders(doc)}
${renderSchemas(doc)}
<footer>
  <p>Generated by <code class="mono">scripts/render-openapi-docs.mjs</code> from <code class="mono">${esc(spec.file)}</code> — static in-repo rendering, no external service. Do not edit the HTML directly; edit the OpenAPI document and re-render.</p>
</footer>
</div>
</body>
</html>`;
  const outPath = resolve(OUT_DIR, spec.out);
  writeFileSync(outPath, html);
  return { outPath, bytes: Buffer.byteLength(html) };
}

function renderIndex(rendered) {
  const cards = rendered.map(({ spec, bytes }) => {
    const name = spec.out.replace(/\.html$/, '');
    return `<a class="card" href="${esc(spec.out)}">
  <div class="card-accent" style="background:${spec.accent}"></div>
  <div class="card-body">
    <div class="card-title">${esc(spec.api)}</div>
    <div class="card-sub">OpenAPI 3.1 contract &middot; <code class="mono">${esc(spec.file)}</code></div>
    <div class="card-meta">${(bytes / 1024).toFixed(0)} KiB static HTML &middot; no external service</div>
  </div>
</a>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenAPI Contracts \u2014 arma-partner-api-sandbox</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; margin: 0; background: #f6f8fa; color: #1f2328; }
  .wrap { max-width: 920px; margin: 0 auto; padding: 40px 24px 64px; }
  h1 { font-size: 26px; margin: 0 0 6px; }
  .sub { color: #59636e; margin: 0 0 28px; font-size: 14px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
  .card { display: flex; border: 1px solid #d1d9e0; background: #fff; border-radius: 8px; text-decoration: none; color: inherit; overflow: hidden; transition: border-color .15s; }
  .card:hover { border-color: #1f6feb; }
  .card-accent { width: 6px; flex: none; }
  .card-body { padding: 16px 18px; }
  .card-title { font-weight: 700; font-size: 17px; margin-bottom: 6px; }
  .card-sub { font-size: 13px; color: #0969da; margin-bottom: 8px; }
  .card-meta { font-size: 12px; color: #59636e; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
  p.note { font-size: 13px; color: #59636e; margin-top: 28px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>OpenAPI Contracts</h1>
  <p class="sub">Machine-readable OpenAPI 3.1.x specifications for the two partner-facing wire contracts, with static in-repo HTML rendering (no external rendering service).</p>
  <div class="cards">
${cards}
  </div>
  <p class="note">The HTML pages are generated by <code class="mono">scripts/render-openapi-docs.mjs</code> (<code class="mono">pnpm run render:openapi-docs</code>) and validated against the live reference implementations in CI by the OpenAPI contract-test lane (<code class="mono">openapi/tests/</code>). Do not edit the HTML directly; edit the OpenAPI document and re-render.</p>
</div>
</body>
</html>`;
}

let failed = 0;
const rendered = [];
for (const spec of SPECS) {
  try {
    const { outPath, bytes } = renderOne(spec);
    rendered.push({ spec, bytes });
    console.log(`rendered ${spec.file} -> ${spec.out} (${(bytes / 1024).toFixed(1)} KiB)`);
  } catch (err) {
    failed++;
    console.error(`FAILED to render ${spec.file}: ${err.message}`);
  }
}

// Static index page linking both contract documents (no external service).
if (rendered.length > 0) {
  const idx = renderIndex(rendered);
  writeFileSync(resolve(OUT_DIR, 'index.html'), idx);
  console.log(`rendered docs/openapi/index.html (${(Buffer.byteLength(idx) / 1024).toFixed(1)} KiB)`);
}

if (failed > 0) process.exit(1);
console.log(`done: ${rendered.length}/${SPECS.length} docs rendered to docs/openapi/` + (rendered.length > 0 ? ' (+ index)' : ''));
