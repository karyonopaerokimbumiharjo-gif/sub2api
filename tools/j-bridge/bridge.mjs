import { realpath } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import Ajv from 'ajv'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

const maxPayload = 2 * 1024 * 1024
const ajv = new Ajv({ strict: true, allErrors: false, validateFormats: false })
export function validateManifest(manifest) {
  if (!manifest || !isAbsolute(manifest.workspace || '') || !Array.isArray(manifest.tools) || !manifest.tools.length || manifest.tools.length > 64) throw Error('invalid_manifest')
  const seen = new Set()
  return manifest.tools.map(tool => {
    const server = manifest.servers?.[tool.server]
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(tool.name) || seen.has(tool.name) || !server || !isAbsolute(server.command || '') || !Array.isArray(server.args) || server.args.some(v => typeof v !== 'string') || !['R0', 'R1', 'R2', 'R3'].includes(tool.risk)) throw Error('invalid_tool_permission')
    if ((server.env || []).some(name => !/^[A-Z_][A-Z_0-9]*$/.test(name) || name === 'SUB2API_API_KEY')) throw Error('invalid_environment')
    seen.add(tool.name)
    return { ...tool, validate: ajv.compile(tool.parameters) }
  })
}

export function apiClient(baseURL, key, fetchFn = fetch) {
  const url = new URL(baseURL)
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) throw Error('https_required')
  if (url.username || url.password || url.search || url.hash) throw Error('invalid_base_url')
  url.pathname = url.pathname.replace(/\/$/, '').replace(/\/v1$/, '') + '/v1/j/bridge/'
  return async (action, body) => {
    const response = await fetchFn(new URL(action, url), { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` }, body: JSON.stringify(body), signal: AbortSignal.timeout(10000) })
    if (!response.ok) throw Error(`bridge_http_${response.status}`)
    const reader = response.body.getReader(); let size = 0; const chunks = []
    try { for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > maxPayload) throw Error('bridge_response_too_large'); chunks.push(value) } } finally { await reader.cancel().catch(() => {}) }
    const envelope = JSON.parse(Buffer.concat(chunks).toString())
    if (envelope.code !== 0 || !Object.hasOwn(envelope, 'data')) throw Error('invalid_bridge_response')
    return envelope.data
  }
}

export async function mcpCall(manifest, tool, args, signal) {
  const server = manifest.servers[tool.server]
  const cwd = await realpath(manifest.workspace)
  const env = { PATH: process.env.PATH || '', HOME: cwd }
  for (const name of server.env || []) { if (process.env[name]) env[name] = process.env[name] }
  const transport = new StdioClientTransport({ command: server.command, args: server.args, cwd, env, stderr: 'ignore' })
  const client = new Client({ name: 'sub2api-authorized-bridge', version: '1.0.0' })
  const close = () => { void client.close().catch(() => {}) }
  signal.addEventListener('abort', close, { once: true })
  try {
    signal.throwIfAborted()
    await client.connect(transport)
    signal.throwIfAborted()
    // Discovery cannot grant permission. Only the locally pinned manifest does.
    let cursor, found
    for (let page = 0; page < 16; page++) {
      const listed = await client.listTools(cursor ? { cursor } : {}, { signal, timeout: 10000 })
      found = listed.tools.find(candidate => candidate.name === tool.name)
      if (found || !listed.nextCursor) break
      cursor = listed.nextCursor
    }
    if (!found || canonical(found.inputSchema) !== canonical(tool.parameters)) throw Error('mcp_schema_changed')
    const result = await client.callTool({ name: tool.name, arguments: args }, undefined, { signal, timeout: 60000 })
    if (Buffer.byteLength(JSON.stringify(result)) > maxPayload) throw Error('tool_output_too_large')
    return result
  } finally { signal.removeEventListener('abort', close); await client.close().catch(() => {}) }
}
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
  return JSON.stringify(value)
}

export async function executeDelivery({ api, grant, delivery, tools, manifest, signal, approve = async () => false, execute = mcpCall }) {
  const tool = tools.find(t => t.name === delivery.call.name)
  if (!tool || Buffer.byteLength(delivery.call.arguments) > maxPayload) throw Error('tool_not_authorized')
  const args = JSON.parse(delivery.call.arguments)
  if (!tool.validate(args)) throw Error('tool_arguments_rejected')
  const lease = { grant_id: grant.id, secret: grant.secret, task_id: delivery.task_id, call_id: delivery.call.call_id, lease: delivery.lease }
  if (!(await api('check', lease)).active) throw Error('tool_lease_inactive')
  const controller = new AbortController()
  const combined = AbortSignal.any([signal, controller.signal, AbortSignal.timeout(Math.min(60000, Math.max(1, Date.parse(delivery.expires_at) - Date.now())))])
  let checking = false
  const timer = setInterval(async () => {
    if (checking) return
    checking = true
    try { if (!(await api('check', lease)).active) controller.abort() } catch { controller.abort() } finally { checking = false }
  }, 500)
  try {
    if (['R2', 'R3'].includes(tool.risk) && !(await approve({ tool: tool.name, arguments: args, callID: delivery.call.call_id, signal: combined }))) throw Error('operator_approval_required')
    combined.throwIfAborted()
    // Recheck after an operator may have spent time reviewing the call.
    if (!(await api('check', lease)).active) throw Error('tool_lease_inactive')
    const output = await execute(manifest, tool, args, combined)
    combined.throwIfAborted()
    await api('complete', { ...lease, output })
  } finally { clearInterval(timer); controller.abort() }
}

export async function runBridge({ manifest, session, api, signal, approve, ready = () => {}, execute }) {
  const tools = validateManifest(manifest)
  const grant = await api('register', { session_id: session, ttl_seconds: 900, tools: tools.map(({ name, parameters, description }) => ({ type: 'function', name, parameters, description })) })
  const seen = new Set()
  try {
    ready({ grant_id: grant.id, session_id: session, expires_at: grant.expires_at })
    while (!signal.aborted && Date.now() < Date.parse(grant.expires_at)) {
      const delivery = await api('poll', { grant_id: grant.id, secret: grant.secret })
      if (!delivery) { await delay(250, null, { signal }); continue }
      const id = `${delivery.task_id}:${delivery.call.call_id}`
      if (seen.has(id)) throw Error('duplicate_tool_delivery')
      seen.add(id)
      // An uncertain effect terminates this grant. Never retry a tool invocation.
      await executeDelivery({ api, grant, delivery, tools, manifest, signal, approve, execute })
    }
  } finally { await api('revoke', { grant_id: grant.id }).catch(() => {}) }
}
