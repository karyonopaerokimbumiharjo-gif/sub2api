// Run the installed Codex CLI through an unchanged, loopback-only HTTP relay.
// No OAuth tokens are read. The provider is explicitly named Sub2API.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync, zstdDecompressSync } from 'node:zlib';
import { once } from 'node:events';
import { modelAcceptance, requestEvidence } from './acceptance.mjs';
import { ResponseObserver } from './response-observer.mjs';

const keyFile = process.env.SUB2API_KEY_FILE;
if (!keyFile || (statSync(keyFile).mode & 0o077)) throw Error('Set SUB2API_KEY_FILE to a private key file');
const apiKey = readFileSync(keyFile, 'utf8').trim();
if (!apiKey) throw Error('Empty API key');
const base = new URL(process.env.SUB2API_BASE_URL || 'http://127.0.0.1:8080/v1');
if (base.username || base.password || base.search || base.hash || (base.hostname !== '127.0.0.1' && base.protocol !== 'https:'))
  throw Error('Use HTTPS or literal loopback, without URL credentials/query/fragment');
const model = process.env.SUB2API_MODEL || 'gpt-6-astra';
const reports = [];
const work = mkdtempSync(join(tmpdir(), 'sub2api-codex-'));
const server = createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/v1/responses' || req.headers.authorization !== `Bearer ${apiKey}`) {
    res.writeHead(404).end(); return;
  }
  const report = { request: reports.length + 1 };
  reports.push(report);
  let observer;
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 8 * 1024 * 1024) throw Error('Request too large');
      chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks);
    const encoding = req.headers['content-encoding'];
    const decoded = encoding === 'gzip' ? gunzipSync(raw) : encoding === 'zstd' ? zstdDecompressSync(raw) : raw;
    const body = JSON.parse(decoded.toString());
    report.requestedModelMatches = body.model === model;
    report.ingress = requestEvidence(req.headers, body);
    const headers = new Headers();
    const excluded = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'accept-encoding', 'keep-alive', 'upgrade', 'te', 'trailer']);
    for (const [key, value] of Object.entries(req.headers))
      if (!excluded.has(key) && value !== undefined) headers.set(key, Array.isArray(value) ? value.join(',') : value);
    const upstream = await fetch(`${base.href.replace(/\/$/, '')}/responses`, {
      method: 'POST', headers, body: raw, redirect: 'error', signal: AbortSignal.timeout(90000),
    });
    report.httpStatus = upstream.status;
    res.writeHead(upstream.status, {'content-type': upstream.headers.get('content-type') || 'application/octet-stream'});
    observer = new ResponseObserver(upstream.headers.get('content-type') || '');
    for await (const chunk of upstream.body) {
      observer.feed(chunk);
      if (!res.write(chunk)) await once(res, 'drain');
    }
    report.observation = observer.finish();
    report.modelAcceptance = modelAcceptance(new Set(report.observation.observedModels), model, process.env.SUB2API_EXPECT_MODELS);
    res.end();
  } catch {
    report.transportError = true;
    if (observer) report.observation = observer.finish(true);
    if (!res.headersSent) res.writeHead(502);
    res.end();
  }
});

try {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const provider = `http://127.0.0.1:${server.address().port}/v1`;
  const config = {
    model_provider: 'sub2api', model_reasoning_effort: 'low',
    'model_providers.sub2api.name': 'Sub2API',
    'model_providers.sub2api.base_url': provider,
    'model_providers.sub2api.wire_api': 'responses',
    'model_providers.sub2api.env_key': 'SUB2API_VERIFY_KEY',
    'model_providers.sub2api.requires_openai_auth': false,
    'model_providers.sub2api.supports_websockets': false,
    'model_providers.sub2api.request_max_retries': 0,
    'model_providers.sub2api.stream_max_retries': 0,
  };
  const args = ['exec', '--ignore-user-config', '--ignore-rules', '--ephemeral', '--skip-git-repo-check',
    '--sandbox', 'read-only', '--cd', work, '--model', model, '--output-last-message', join(work, 'answer.txt')];
  for (const [key, value] of Object.entries(config)) args.push('-c', `${key}=${JSON.stringify(value)}`);
  args.push('Reply with exactly CODEX_SUB2API_OK. Do not call tools or inspect any files.');
  const child = spawn(process.env.CODEX_BIN || 'codex', args, {env: {...process.env, SUB2API_VERIFY_KEY: apiKey}, stdio: ['ignore', 'pipe', 'pipe']});
  // Do not print CLI diagnostics: provider errors can contain request content.
  child.stdout.resume(); child.stderr.resume();
  const timer = setTimeout(() => child.kill('SIGKILL'), 120000);
  let code;
  try { [code] = await once(child, 'close'); } finally { clearTimeout(timer); }
  let finalTextMatches = false;
  try { finalTextMatches = readFileSync(join(work, 'answer.txt'), 'utf8').trim() === 'CODEX_SUB2API_OK'; } catch {}
  const protocolPassed = code === 0 && finalTextMatches && reports.length > 0 && reports.every(r =>
    !r.transportError && r.requestedModelMatches && r.httpStatus === 200 && r.ingress?.stream && r.ingress?.inputPresent &&
    r.observation?.terminal_status === 'completed' && !r.observation.stream_interrupted && !r.observation.modelOverflow);
  const modelPassed = reports.length > 0 && reports.every(r => r.modelAcceptance?.passed);
  console.log(JSON.stringify({client: 'codex', requestedModel: model, protocolPassed, modelPassed, finalTextMatches, requests: reports}));
  if (!protocolPassed || !modelPassed) process.exitCode = 1;
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  rmSync(work, {recursive: true, force: true});
}
