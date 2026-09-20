import { test } from 'node:test';
import assert from 'node:assert/strict';
import { modelAcceptance, requestEvidence } from './acceptance.mjs';
import { stream as streamCodex } from '@earendil-works/pi-ai/api/openai-codex-responses';
import { zstdDecompressSync } from 'node:zlib';

test('model acceptance rejects missing, mismatched, and mixed declarations', () => {
  for (const values of [[], ['gpt-5.6-luna'], ['gpt-6-astra', 'gpt-5.6-luna']])
    assert.equal(modelAcceptance(new Set(values), 'gpt-6-astra').passed, false);
  assert.equal(modelAcceptance(new Set(['gpt-6-astra']), 'gpt-6-astra').passed, true);
  assert.equal(modelAcceptance(new Set(['gpt-5.6-luna']), 'gpt-5.5').passed, false);
});

test('request evidence reports field presence without leaking values', () => {
  const evidence = requestEvidence({authorization: 'Bearer SECRET', originator: 'private-origin',
    'x-codex-turn-metadata': JSON.stringify({session_id: 'SECRET', unknown: 'SECRET'})},
    {input: 'SECRET', stream: true, store: false, previous_response_id: 'SECRET'});
  assert.equal(JSON.stringify(evidence).includes('SECRET'), false);
  assert.equal(evidence.originator, 'other');
  assert.deepEqual(evidence.headerMetadata.idsPresent, ['session_id']);
  assert.equal(evidence.previousResponseIDPresent, true);
});

test('embedded and malformed metadata are distinguished from absent metadata', () => {
  assert.equal(requestEvidence({}, {}).headerMetadata.present, false);
  assert.equal(requestEvidence({'x-codex-turn-metadata': 'invalid'}, {}).headerMetadata.present, true);
  assert.deepEqual(requestEvidence({}, {client_metadata: {'x-codex-turn-metadata': '{"turn_id":"secret"}'}}).bodyMetadata.idsPresent, ['turn_id']);
});

test('header and body metadata are audited independently', () => {
 const evidence = requestEvidence({'x-codex-turn-metadata':'{"thread_id":"secret-a"}'},
   {client_metadata:{'x-codex-turn-metadata':'{"session_id":"secret-b"}'}});
 assert.deepEqual(evidence.headerMetadata.idsPresent,['thread_id']);
 assert.deepEqual(evidence.bodyMetadata.idsPresent,['session_id']);
 assert.equal(JSON.stringify(evidence).includes('secret-'),false);
});

test('pinned Pi native adapter generates no turn metadata and preserves supplied metadata', async () => {
  // Synthetic JWT, intercepted fetch: no real credentials or network calls.
  const token = `test.${Buffer.from(JSON.stringify({'https://api.openai.com/auth': {chatgpt_account_id: 'fixture-account'}})).toString('base64url')}.test`;
  const model = {id: 'gpt-6-astra', name: 'fixture', provider: 'openai-codex', api: 'openai-codex-responses',
    baseUrl: 'https://fixture.invalid/backend-api', reasoning: true, input: ['text'],
    cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0}, contextWindow: 128000, maxTokens: 1024};
  for (const supplied of [undefined, '{"turn_id":"fixture-turn"}']) {
    let captured;
    const response = streamCodex(model, {systemPrompt: 'Fixture instructions', messages: [
      {role: 'user', content: 'Fixture input', timestamp: 0},
    ]}, {apiKey: token, transport: 'sse', sessionId: 'fixture-session', maxRetries: 0,
      headers: supplied ? {'x-codex-turn-metadata': supplied} : undefined,
      fetch: async (_url, init) => {
        const headers = new Headers(init.headers);
        const raw = headers.get('content-encoding') === 'zstd' ? zstdDecompressSync(init.body).toString() : init.body;
        captured = {headers, body: JSON.parse(raw)};
        return new Response('data: {"type":"response.completed","response":{"id":"resp_fixture","status":"completed","model":"gpt-6-astra","output":[],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}}\n\n',
          {headers: {'content-type': 'text/event-stream'}});
      }});
    for await (const _event of response) { /* consume the real adapter */ }
    assert.equal((await response.result()).stopReason, 'stop');
    assert.equal(captured.headers.get('originator'), 'pi');
    assert.equal(captured.headers.get('chatgpt-account-id'), 'fixture-account');
    assert.equal(captured.headers.get('session-id'), 'fixture-session');
    assert.equal(captured.headers.get('x-codex-turn-metadata'), supplied ?? null);
    assert.equal(Object.hasOwn(captured.body, 'client_metadata'), false);
    assert.equal(captured.body.store, false);
    assert.equal(captured.body.stream, true);
    assert.equal(captured.body.instructions, 'Fixture instructions');
    assert.deepEqual(captured.body.include, ['reasoning.encrypted_content']);
  }
});
