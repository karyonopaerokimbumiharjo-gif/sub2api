// Redacted evidence only: never return credentials, prompts, or identifier values.
export function requestEvidence(headers, body) {
  const h = new Headers(headers);
  const headerMetadata = metadataEvidence(h.get('x-codex-turn-metadata'));
  const bodyMetadata = metadataEvidence(body.client_metadata?.['x-codex-turn-metadata']);
  const originator = h.get('originator');
  return {
    originator: originator === null ? 'absent' : ['pi', 'codex-tui', 'codex_cli_rs'].includes(originator) ? originator : 'other',
    headerMetadata, bodyMetadata,
    stream: body.stream === true,
    store: typeof body.store === 'boolean' ? body.store : 'unspecified',
    inputPresent: Object.hasOwn(body, 'input'),
    toolsPresent: Array.isArray(body.tools) && body.tools.length > 0,
    previousResponseIDPresent: typeof body.previous_response_id === 'string',
  };
}

export function modelAcceptance(observed, requested, expectedOverride) {
  const expected = (expectedOverride || (['gpt-6', 'gpt-6-astra'].includes(requested) ? 'gpt-6,gpt-6-astra' : requested))
    .split(',').map(x => x.trim()).filter(Boolean);
  return { expected, observed: [...observed], passed: observed.size > 0 && [...observed].every(m => expected.includes(m)) };
}

function metadataEvidence(raw) {
  let metadata;
  try { if (typeof raw === 'string') metadata = JSON.parse(raw); } catch {}
  const object = metadata !== null && typeof metadata === 'object' && !Array.isArray(metadata);
  return {present: raw != null, validObject: object,
    idsPresent: ['installation_id', 'session_id', 'thread_id', 'turn_id', 'window_id'].filter(k => object && Object.hasOwn(metadata, k))};
}
