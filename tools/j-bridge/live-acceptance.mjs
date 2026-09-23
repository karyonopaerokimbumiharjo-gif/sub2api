// Opt-in acceptance against a real gateway. Never prints the supplied API key.
// SUB2API_API_KEY_FILE contains a temporary key object created by the operator.
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { apiClient, runBridge } from './bridge.mjs'

const key = JSON.parse(await readFile(process.env.SUB2API_API_KEY_FILE, 'utf8')).key
const base = process.env.SUB2API_BASE_URL
const model = process.env.SUB2API_ACCEPTANCE_MODEL || 'gpt-5.6-sol-j'
const workspace = await mkdtemp(join(tmpdir(), 'j-live-acceptance-'))
const session = 'j-live-' + randomUUID(), task = randomUUID()
const controller = new AbortController()
const watchdog = setTimeout(() => controller.abort(), 210000)
let responseWork, result
try {
  await writeFile(join(workspace,'note.txt'),'FIRST_FILE_OBSERVED')
  await writeFile(join(workspace,'proof.txt'),'SECOND_FILE_OBSERVED')
  const parameters = {type:'object',properties:{file:{type:'string',enum:['note.txt','proof.txt']}},required:['file'],additionalProperties:false}
  const manifest = {device_id:'authorized-live-acceptance-device',workspace,servers:{files:{command:process.execPath,args:[fileURLToPath(new URL('./fixtures/sequence-server.mjs',import.meta.url))]}},tools:[{name:'read_fixture',server:'files',risk:'R1',description:'Read one authorized acceptance fixture file.',parameters}]}
  try {
    await runBridge({manifest,session,task,api:apiClient(base,key),signal:controller.signal,
      ready:info => {
        responseWork = (async () => {
          const started=Date.now()
          const response=await fetch(base+'/v1/responses',{method:'POST',headers:{authorization:'Bearer '+key,'content-type':'application/json','session-id':session,'Idempotency-Key':task,'X-Sub2API-Tool-Grant':info.grant_id},signal:AbortSignal.timeout(195000),body:JSON.stringify({model,input:'Read note.txt first with read_fixture. After observing that result, read proof.txt with read_fixture. Read each file once. Then report the two observed file markers and finish with J_LOCAL_BRIDGE_OK.',tools:[{type:'function',name:'read_fixture',description:manifest.tools[0].description,parameters,strict:true}],tool_choice:'auto',stream:false})})
          const body=await response.json()
          const text=JSON.stringify(body.output||[])
          result={task,model,http:response.status,status:body.status,first_observed:text.includes('FIRST_FILE_OBSERVED'),second_observed:text.includes('SECOND_FILE_OBSERVED'),final_marker:text.includes('J_LOCAL_BRIDGE_OK'),seconds:(Date.now()-started)/1000,error:body.error?.type||body.code}
        })().finally(()=>controller.abort())
      }
    })
  } catch(error) { if(!controller.signal.aborted)throw error }
  await responseWork
  console.log(JSON.stringify(result))
  if(!result || result.http!==200 || !result.first_observed || !result.second_observed || !result.final_marker)process.exitCode=1
} finally {clearTimeout(watchdog);controller.abort();await rm(workspace,{recursive:true,force:true})}
