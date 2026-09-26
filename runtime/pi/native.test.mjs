import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {WebSocketServer} from 'ws';
import {zstdDecompressSync} from 'node:zlib';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runNative,nativeBody,scopedSession,closeSessions} from './native.mjs';
import {createRuntime,nativeFailure} from './server.mjs';
import {checkRuntimeHealth} from './healthcheck.mjs';
const token=account=>`test.${Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:account}})).toString('base64url')}.test`;
const request={model:'gpt-6-astra',input:[{role:'user',content:[{type:'input_text',text:'fixture'}]}]};
const base={request,accessToken:token('account-a'),accountId:'account-a',ownerId:1,credentialId:5,sessionId:'s1',sessionSecret:'test-secret',onBytes:()=>{}};
test('runtime returns one classified failure without leaking provider details',async()=>{
 assert.deepEqual(nativeFailure(200,{errorMessage:'Codex error: Our servers are currently overloaded. Please try again later.'}),{status:503,code:'pi_upstream_busy'});
 assert.deepEqual(nativeFailure(200,{errorMessage:'private payload and credential'}),{status:502,code:'pi_upstream_failed'});
 for(const status of [401,403,429,503,502]){
  const secret='a'.repeat(40);
  const server=createRuntime({secret,native:async options=>{
   options.onHeaders(status,new Headers());
   return {evidence:{terminal_status:'failed'},result:{errorMessage:'private provider payload'}};
  }});
  server.listen(0,'127.0.0.1');await once(server,'listening');
  try{
   const response=await fetch(`http://127.0.0.1:${server.address().port}/responses`,{method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},body:JSON.stringify({request})});
   assert.equal(response.status,status);
   assert.deepEqual(await response.json(),{error:nativeFailure(status,{}).code});
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
 }
});
test('standalone compact is forwarded through the bound OAuth identity',async()=>{
 const secret='a'.repeat(40);let outbound;
 const server=createRuntime({secret,compactFetch:async(url,init)=>{
  outbound={url,init,body:JSON.parse(init.body)};
  return new Response(JSON.stringify({id:'cmp_fixture',object:'response.compaction',output:[]}),{status:200,headers:{'content-type':'application/json','x-request-id':'compact-fixture'}});
 }});
 server.listen(0,'127.0.0.1');await once(server,'listening');
 try {
  const response=await fetch(`http://127.0.0.1:${server.address().port}/compact`,{method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},body:JSON.stringify({owner_id:1,account_id:'account-a',access_token:token('account-a'),request:{model:'gpt-6-astra',input:[{role:'user',content:'fixture'}]}})});
  assert.equal(response.status,200);assert.equal((await response.json()).id,'cmp_fixture');
  assert.equal(outbound.url,'https://chatgpt.com/backend-api/codex/responses/compact');
  assert.equal(outbound.init.headers['chatgpt-account-id'],'account-a');
  assert.equal(outbound.init.headers.originator,'codex_cli_rs');
  assert.equal(outbound.body.store,false);assert.equal(outbound.body.stream,false);
 } finally {server.closeAllConnections();await new Promise(r=>server.close(r))}
});
function completed(id){return JSON.stringify({type:'response.completed',response:{id,status:'completed',model:'gpt-6-astra',output:[],usage:{input_tokens:1,output_tokens:0,total_tokens:1}}})}
test('native SDK produces its own headers, preserves Responses input, and streams exact bytes',async()=>{
 let outbound;const bytes=Buffer.from(`data: ${completed('resp_one')}\n\n`);const output=[];
 const result=await runNative({...base,transport:'sse',onBytes:b=>output.push(Buffer.from(b)),fetchImpl:async(url,init)=>{
  const headers=new Headers(init.headers);const body=JSON.parse(headers.get('content-encoding')==='zstd'?zstdDecompressSync(init.body).toString():init.body);
  outbound={url,headers,body};return new Response(bytes,{headers:{'content-type':'text/event-stream'}});
 }});
 assert.equal(result.evidence.terminal_status,'completed');assert.equal(result.evidence.stream_interrupted,true,'Pi closes SSE after its first terminal, before EOF');assert.deepEqual(Buffer.concat(output),bytes);
 assert.equal(outbound.headers.get('originator'),'pi');assert.equal(outbound.headers.has('x-codex-turn-metadata'),false);
 assert.equal(outbound.headers.get('chatgpt-account-id'),'account-a');assert.deepEqual(outbound.body.input,request.input);
 assert.equal(outbound.body.store,false);assert.equal(outbound.body.stream,true);
 assert.notEqual(outbound.body.prompt_cache_key,'s1');
});
test('bindings separate users, accounts, models and credentials, but remain stable across refresh',async()=>{
 const args=['secret',1,5,'account-a','gpt-6-astra','s1'];const original=scopedSession(...args);
 assert.equal(original,scopedSession(...args));
 for(const index of [1,2,3,4,5]){const copy=[...args];copy[index]='different';assert.notEqual(original,scopedSession(...copy))}
 let called=false;await assert.rejects(runNative({...base,accountId:'account-b',fetchImpl:()=>{called=true}}),/oauth_account_mismatch/);assert.equal(called,false);
 assert.throws(()=>nativeBody({...request,previous_response_id:'other-user-response'},{}),/unsupported_pi_field/);
 assert.throws(()=>nativeBody({...request,client_metadata:{}},{}),/unsupported_pi_field/);
});
test('max_output_tokens is accepted and forwarded to the Pi SDK',async()=>{
 const limited={...request,max_output_tokens:64};
 assert.equal(nativeBody(limited,{}).max_output_tokens,64);
 const bytes=Buffer.from(`data: ${completed('resp_limited')}\n\n`);
 let contacted=false;
 const result=await runNative({...base,request:limited,fetchImpl:async()=>{
  contacted=true;
  return new Response(bytes,{headers:{'content-type':'text/event-stream'}});
 }});
 assert.equal(contacted,true);
 assert.equal(result.evidence.terminal_status,'completed');
});
test('authenticated readiness probe fails on missing, wrong, or stopped runtime',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'pi-health-'));const secretFile=join(dir,'runtime.secret');
 const secret='a'.repeat(40);writeFileSync(secretFile,secret,{mode:0o600});
 const server=createRuntime({secret});server.listen(0,'127.0.0.1');await once(server,'listening');
 const port=server.address().port;
 try {
  assert.equal(await checkRuntimeHealth({secretFile,port}),true);
  assert.equal(await checkRuntimeHealth({secretFile:join(dir,'missing.secret'),port}),false);
  writeFileSync(secretFile,'b'.repeat(40));
  assert.equal(await checkRuntimeHealth({secretFile,port}),false);
  await new Promise(r=>server.close(r));
  assert.equal(await checkRuntimeHealth({secretFile,port}),false);
 }finally{server.closeAllConnections();if(server.listening)await new Promise(r=>server.close(r));rmSync(dir,{recursive:true,force:true})}
});
test('real Pi WS cache reuses connections, sends delta, and isolates credential namespace',async()=>{
 const http=createServer();const wss=new WebSocketServer({server:http});const seen=[];
 wss.on('connection',socket=>socket.on('message',raw=>{seen.push(JSON.parse(raw));socket.send(completed(`resp_${seen.length}`))}));
 http.listen(0,'127.0.0.1');await once(http,'listening');const url=`http://127.0.0.1:${http.address().port}/backend-api`;
 try{
  const first=await runNative({...base,baseUrl:url,transport:'websocket-cached'});assert.equal(first.evidence.terminal_status,'completed');
  const next={...request,input:[...request.input,{role:'user',content:[{type:'input_text',text:'next'}]}]};
  const second=await runNative({...base,request:next,baseUrl:url,transport:'websocket-cached'});
  assert.equal(second.continuation.connectionsReused,1);assert.equal(second.continuation.deltaRequests,1);
  assert.equal(seen[1].previous_response_id,'resp_1');assert.equal(seen[1].input.length,1);
  await runNative({...base,credentialId:6,request:next,baseUrl:url,transport:'websocket-cached'});
  assert.equal(seen[2].previous_response_id,undefined);assert.equal(seen[2].input.length,2);
 }finally{closeSessions();for(const socket of wss.clients)socket.terminate();wss.close();http.closeAllConnections();await new Promise(r=>http.close(r))}
});
test('private runtime requires its key and binds OAuth callbacks to the initiating owner and state',async()=>{
 const secret='a'.repeat(40);let exchangeInput;
 const oauth={async login(i){await i.prompt({type:'select'});i.notify({type:'auth_url',url:'https://auth.openai.com/oauth/authorize?state=fixture-state&originator=pi'});
  exchangeInput=await i.prompt({type:'manual_code',signal:i.signal});return {access:token('account-a'),refresh:'fixture-refresh',expires:Date.now()+3600000}},
  async refresh(){return {access:token('wrong-account'),refresh:'fixture',expires:Date.now()+3600000}}};
 const server=createRuntime({secret,oauth});server.listen(0,'127.0.0.1');await once(server,'listening');
 const root=`http://127.0.0.1:${server.address().port}`;
 const post=(path,body)=>fetch(root+path,{method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},body:JSON.stringify(body)});
 try{
  assert.equal((await fetch(root+'/health')).status,401);
  const start=await(await post('/oauth/start',{owner_id:1})).json();assert.ok(start.session_id);
  const callback='http://localhost:1455/auth/callback?state=fixture-state&code=fixture-code';
  assert.equal((await post('/oauth/complete',{session_id:start.session_id,owner_id:2,callback_url:callback})).status,400);
  assert.equal((await post('/oauth/complete',{session_id:start.session_id,owner_id:1,callback_url:callback.replace('fixture-state','bad-state')})).status,400);
  const completed=await(await post('/oauth/complete',{session_id:start.session_id,owner_id:1,callback_url:callback})).json();
  assert.equal(completed.harness_kind,'pi');assert.equal(completed.pi_owner_user_id,'1');assert.equal(exchangeInput,callback);
  assert.deepEqual(await(await post('/oauth/complete',{session_id:start.session_id,owner_id:1,callback_url:callback})).json(),completed);
  assert.equal((await post('/oauth/ack',{session_id:start.session_id,owner_id:2})).status,400);
  assert.equal((await post('/oauth/ack',{session_id:start.session_id,owner_id:1})).status,200);
  assert.equal((await post('/oauth/complete',{session_id:start.session_id,owner_id:1,callback_url:callback})).status,400);
  assert.equal((await post('/oauth/refresh',{account_id:'account-a',owner_id:1,refresh_token:'fixture'})).status,400);
 }finally{server.closeAllConnections();await new Promise(r=>server.close(r))}
});

test('concurrent turns in the same Pi session run independently without queuing',{timeout:5000},async()=>{
 let release,entered;const ready=new Promise(resolve=>entered=resolve);
 const hold=new Promise(resolve=>release=resolve);
 const first=runNative({...base,transport:'sse',fetchImpl:async()=>{entered();await hold;return new Response(`data: ${completed('one')}\n\n`,{headers:{'content-type':'text/event-stream'}})}});
 await ready;
 try{
  const second=await runNative({...base,transport:'sse',fetchImpl:async()=>new Response('data: '+completed('two')+String.fromCharCode(10,10),{headers:{'content-type':'text/event-stream'}})});
  assert.equal(second.evidence.terminal_status,'completed');
 }
 finally{release();await first}
});

test('cached request input is isolated from caller mutations',()=>{
 const original=structuredClone(request);const body=nativeBody(original,{instructions:'test'});
 original.input.push({role:'user',content:'mutated'});
 assert.equal(body.input.length,1);
});

test('two callers share one credential concurrently; cancelling one cached WS turn preserves the other', {timeout:5000}, async()=>{
 const http=createServer();const wss=new WebSocketServer({server:http});
 const sent=[];let both;const ready=new Promise(resolve=>both=resolve);
 wss.on('connection',socket=>socket.on('message',raw=>{
  const body=JSON.parse(raw);sent.push({socket,body});if(sent.length===2)both();
 }));
 http.listen(0,'127.0.0.1');await once(http,'listening');const baseUrl=`http://127.0.0.1:${http.address().port}/backend-api`;
 const cancelA=new AbortController();const outputA=[],outputB=[];
 const call=(sessionId,signal,onBytes)=>runNative({...base,baseUrl,sessionId,signal,onBytes,transport:'websocket-cached'});
 try {
  const a=call('42:11:shared-name',cancelA.signal,b=>outputA.push(Buffer.from(b)));
  const b=call('43:12:shared-name',undefined,b=>outputB.push(Buffer.from(b)));
  await ready;
  assert.notEqual(sent[0].body.prompt_cache_key,sent[1].body.prompt_cache_key);
  cancelA.abort();
  const resultA=await a;
  assert.equal(resultA.result.stopReason,'aborted');
  const bScope=scopedSession(base.sessionSecret,base.ownerId,base.credentialId,base.accountId,request.model,'43:12:shared-name');
  const bSocket=sent.find(item=>item.body.prompt_cache_key===bScope)?.socket;
  assert.ok(bSocket);bSocket.send(completed('only_b_completed'));
  const resultB=await b;
  assert.equal(resultB.evidence.terminal_status,'completed');
  assert.match(Buffer.concat(outputB).toString(),/only_b_completed/);
  assert.doesNotMatch(Buffer.concat(outputA).toString(),/only_b_completed/);
 } finally {
  cancelA.abort();closeSessions();for(const socket of wss.clients)socket.terminate();wss.close();http.closeAllConnections();await new Promise(r=>http.close(r));
 }
});

test('same session uses independent cached WS lanes; cancelling one preserves the other', {timeout:5000}, async()=>{
 const http=createServer();const wss=new WebSocketServer({server:http});
 const sent=[];let both;const ready=new Promise(resolve=>both=resolve);
 wss.on('connection',socket=>socket.on('message',raw=>{
  const body=JSON.parse(raw);sent.push({socket,body});if(sent.length===2)both();
 }));
 http.listen(0,'127.0.0.1');await once(http,'listening');const baseUrl=`http://127.0.0.1:${http.address().port}/backend-api`;
 const cancelA=new AbortController();const outputA=[],outputB=[];
 const call=(sessionId,signal,onBytes)=>runNative({...base,baseUrl,sessionId,signal,onBytes,transport:'websocket-cached'});
 try {
  const a=call('42:11:shared-name',cancelA.signal,b=>outputA.push(Buffer.from(b)));
  const b=call('42:11:shared-name',undefined,b=>outputB.push(Buffer.from(b)));
  await ready;
  assert.notEqual(sent[0].body.prompt_cache_key,sent[1].body.prompt_cache_key);
  cancelA.abort();
  const resultA=await a;
  assert.equal(resultA.result.stopReason,'aborted');
  const bScope=scopedSession(base.sessionSecret,base.ownerId,base.credentialId,base.accountId,request.model,'42:11:shared-name');
  const bSocket=sent.find(item=>item.body.prompt_cache_key!==bScope)?.socket;
  assert.ok(bSocket);bSocket.send(completed('only_b_completed'));
  const resultB=await b;
  assert.equal(resultB.evidence.terminal_status,'completed');
  assert.match(Buffer.concat(outputB).toString(),/only_b_completed/);
  assert.doesNotMatch(Buffer.concat(outputA).toString(),/only_b_completed/);
 } finally {
  cancelA.abort();closeSessions();for(const socket of wss.clients)socket.terminate();wss.close();http.closeAllConnections();await new Promise(r=>http.close(r));
 }
});
