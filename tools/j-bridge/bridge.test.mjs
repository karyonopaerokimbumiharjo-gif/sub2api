import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { executeDelivery, validateManifest, mcpCall, apiClient } from './bridge.mjs'

const parameters = { type: 'object', properties: { file: { type: 'string', enum: ['note.txt'] } }, required: ['file'], additionalProperties: false }
const manifest = { device_id:'fixture-device', workspace: tmpdir(), servers: { fixture: { command: process.execPath, args: [fileURLToPath(new URL('./fixtures/server.mjs', import.meta.url))] } }, tools: [{ name: 'read_fixture', server: 'fixture', risk: 'R1', parameters }] }
const delivery = () => ({ task_id: 'task-a', call: { call_id: 'call-a', name: 'read_fixture', arguments: '{"file":"note.txt"}' }, lease: 'fixture-lease', expires_at: new Date(Date.now()+60000).toISOString() })

test('real local MCP discovery and authorized file read', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'j-bridge-test-'))
  try {
    await writeFile(join(workspace,'note.txt'),'LOCAL_BRIDGE_OK')
    const config = { ...manifest, workspace }, tools = validateManifest(config)
    const output = await mcpCall(config, tools[0], { file: 'note.txt' }, AbortSignal.timeout(10000))
    assert.equal(output.content[0].text, 'LOCAL_BRIDGE_OK')
    await assert.rejects(mcpCall(config, {...tools[0], parameters: {type:'object'}}, {}, AbortSignal.timeout(10000)), /mcp_schema_changed/)
  } finally { await rm(workspace,{recursive:true,force:true}) }
})

test('schema, permissions and lease checked before effects', async () => {
  let calls = 0
  const options = { api: async () => ({active:true}), grant:{id:'grant',secret:'private',task_id:'task-a',device_id:'fixture-device'}, delivery:delivery(), tools:validateManifest(manifest), manifest, signal:new AbortController().signal, execute:async()=>{calls++; return {ok:true}} }
  const changed=delivery(); changed.call.arguments='{"file":"../../private","extra":true}'
  await assert.rejects(executeDelivery({...options,delivery:changed}),/tool_arguments_rejected/)
  await assert.rejects(executeDelivery({...options,api:async()=>({active:false})}),/tool_lease_inactive/)
  await assert.rejects(executeDelivery({...options,tools:[{...options.tools[0],risk:'R3'}]}),/operator_approval_required/)
  await assert.rejects(executeDelivery({...options,delivery:{...delivery(),task_id:'other-task'}}),/tool_binding_mismatch/)
  await assert.rejects(executeDelivery({...options,grant:{...options.grant,device_id:'other-device'}}),/tool_binding_mismatch/)
  assert.equal(calls,0)
  await executeDelivery(options)
  assert.equal(calls,1)
})

test('revoked running lease aborts child and never submits result', async () => {
  let active = true, completed = 0
  const api = async action => { if(action==='complete') completed++; return {active} }
  const run = executeDelivery({api,grant:{id:'g',secret:'s',task_id:'task-a',device_id:'fixture-device'},delivery:delivery(),tools:validateManifest(manifest),manifest,signal:new AbortController().signal,
    execute:async(_m,_t,_a,signal)=>new Promise((resolve,reject)=>{ active=false; signal.addEventListener('abort',()=>reject(Error('cancelled')),{once:true}) }) })
  await assert.rejects(run,/cancelled/)
  assert.equal(completed,0)
})

test('remote cleartext and credential-bearing base URLs rejected',()=>{
  assert.throws(()=>apiClient('http://example.com','secret'),/https_required/)
  assert.throws(()=>apiClient('https://user:secret@example.com','secret'),/invalid_base_url/)
  assert.throws(()=>validateManifest({...manifest,tools:[{...manifest.tools[0],risk:'R4'}]}),/invalid_tool_permission/)
})
