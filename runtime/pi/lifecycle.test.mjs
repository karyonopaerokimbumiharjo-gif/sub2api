import {test} from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {createRuntime} from './server.mjs';
import {runNative} from './native.mjs';

const secret='s'.repeat(40);
const token=`test.${Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:'account-a'}})).toString('base64url')}.test`;
const request={model:'gpt-6-astra',input:'fixture'};
const payload={request,access_token:token,account_id:'account-a',owner_id:1,credential_id:5,session_id:'lifecycle',transport:'sse'};
const frame=value=>Buffer.from(`data: ${JSON.stringify(value)}\n\n`);
const created={type:'response.created',sequence_number:0,response:{id:'resp_fixture',object:'response',status:'in_progress',model:'gpt-6-astra',output:[]}};
const terminal=status=>({type:`response.${status}`,sequence_number:1,response:{...created.response,status,usage:{input_tokens:1,output_tokens:0,total_tokens:1},...(status==='failed'?{error:{code:'server_error',message:'fixture'}}:{})}});
const events=text=>text.split('\n').filter(line=>line.startsWith('data: ')).map(line=>JSON.parse(line.slice(6)));

async function withRuntime(options,check) {
 const runtime=createRuntime({secret,...options});runtime.listen(0,'127.0.0.1');await once(runtime,'listening');
 const post=(body=payload,signal)=>fetch(`http://127.0.0.1:${runtime.address().port}/responses`,{
  method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},body:JSON.stringify(body),signal});
 try{return await check(post)}finally{runtime.closeAllConnections();await new Promise(resolve=>runtime.close(resolve))}
}
function fakeClock() {
 let now=0;const pending=new Set();
 return {setTimeout(fn,delay){const item={fn,at:now+delay,unref(){}};pending.add(item);return item},
  clearTimeout(item){pending.delete(item)},
  tick(ms){now+=ms;for(const item of [...pending])if(item.at<=now){pending.delete(item);item.fn()}},
  get pending(){return pending.size}};
}

for(const mode of ['eof','socket-error'])test(`real SDK ${mode} after created receives one safe failure terminal`,async()=>{
 const native=options=>runNative({...options,fetchImpl:async()=>{
  let pulls=0;
  return new Response(new ReadableStream({pull(controller){
   if(pulls++===0){controller.enqueue(frame(created));return}
   if(mode==='socket-error')controller.error(Error('private-provider-token-must-not-leak'));
   else controller.close();
  }},{highWaterMark:0}),{headers:{'content-type':'text/event-stream'}});
 }});
 await withRuntime({native},async post=>{
  const response=await post();assert.equal(response.status,200);
  const text=await response.text();const output=events(text);
  assert.deepEqual(output.map(event=>event.type),['response.created','response.failed']);
  assert.equal(output[1].response.id,'resp_fixture');assert.equal(output[1].sequence_number,1);
  assert.equal(output[1].response.error.code,'pi_upstream_failed');
  assert.doesNotMatch(text,/private-provider-token-must-not-leak/);
 });
});

test('post-header exceptions become failure terminals and pre-header exceptions retain JSON errors',async()=>{
 for(const started of [false,true])await withRuntime({native:async options=>{
  if(started)await options.onBytes(frame(created));
  throw Error('private-provider-token-must-not-leak');
 }},async post=>{
  const response=await post();const text=await response.text();assert.doesNotMatch(text,/private-provider-token-must-not-leak/);
  if(started){assert.equal(response.status,200);assert.equal(events(text).at(-1).type,'response.failed')}
  else{assert.equal(response.status,400);assert.deepEqual(JSON.parse(text),{error:'pi_runtime_error'})}
 });
});

for(const status of ['completed','failed','incomplete'])test(`a real ${status} terminal is preserved without duplication`,async()=>{
 await withRuntime({native:async options=>{
  await options.onBytes(frame(created));await options.onBytes(frame(terminal(status)));
  // A transport close after a terminal must not invent a second terminal.
  throw Error('socket closed after terminal');
 }},async post=>{
  const output=events(await(await post()).text());
  assert.deepEqual(output.map(event=>event.type),['response.created',`response.${status}`]);
 });
});

for(const status of ['completed','failed','incomplete'])test(`large ${status} terminal does not receive a conflicting fallback`,async()=>{
 const ending=terminal(status);ending.response.output=[{id:'msg_fixture',type:'message',status:'completed',role:'assistant',content:[{type:'output_text',text:'x'.repeat(300000),annotations:[]}]}];
 const native=options=>runNative({...options,fetchImpl:async()=>new Response(Buffer.concat([frame(created),frame(ending)]),{headers:{'content-type':'text/event-stream'}})});
 await withRuntime({native},async post=>{
  const output=events(await(await post()).text());
  assert.deepEqual(output.map(event=>event.type),['response.created',`response.${status}`]);
 });
});

test('active streams can exceed old total caps; only configured idle gaps abort and timers are cleaned',async()=>{
 const clock=fakeClock();
 await withRuntime({timers:clock,native:async options=>{
  options.onHeaders(200,new Headers());await options.onBytes(frame(created));
  for(let i=0;i<10;i++){
   clock.tick(100000);assert.equal(options.signal.aborted,false);
   await options.onBytes(Buffer.from(': upstream progress\n\n'));
  }
  await options.onBytes(frame(terminal('completed')));
  return {evidence:{terminal_status:'completed'},result:{}};
 }},async post=>{
  assert.equal(events(await(await post()).text()).at(-1).type,'response.completed');
 });
 assert.equal(clock.pending,0);
 await withRuntime({timers:clock,native:async options=>{
  options.onHeaders(200,new Headers());await options.onBytes(frame(created));
  clock.tick(179999);assert.equal(options.signal.aborted,false);
  clock.tick(1);assert.equal(options.signal.aborted,true);
  return {evidence:{terminal_status:null},result:{stopReason:'aborted'}};
 }},async post=>{
  const output=events(await(await post({...payload,response_header_timeout_ms:73000,stream_idle_timeout_ms:180000})).text());
  assert.equal(output.at(-1).response.error.code,'pi_upstream_timeout');
 });
 assert.equal(clock.pending,0);
});

test('header deadline ends before first bytes, then hands off to the independent idle deadline',async()=>{
 const clock=fakeClock();
 await withRuntime({timers:clock,native:async options=>{
  clock.tick(72999);assert.equal(options.signal.aborted,false);
  clock.tick(1);assert.equal(options.signal.aborted,true);
  return {evidence:{terminal_status:null},result:{stopReason:'aborted'}};
 }},async post=>{
  const response=await post({...payload,response_header_timeout_ms:73000,stream_idle_timeout_ms:180000});
  assert.equal(response.status,504);assert.deepEqual(await response.json(),{error:'pi_upstream_timeout'});
 });
 assert.equal(clock.pending,0);
 await withRuntime({timers:clock,native:async options=>{
  clock.tick(70000);options.onHeaders(200,new Headers());await options.onBytes(frame(created));
  clock.tick(100000);assert.equal(options.signal.aborted,false,'old header deadline must be cleared after headers');
  await options.onBytes(frame(terminal('completed')));
  return {evidence:{terminal_status:'completed'},result:{}};
 }},async post=>{
  assert.equal(events(await(await post({...payload,response_header_timeout_ms:73000,stream_idle_timeout_ms:180000})).text()).at(-1).type,'response.completed');
 });
 assert.equal(clock.pending,0);
});

test('explicit zero idle timeout is honored and invalid timeout settings fail before native invocation',async()=>{
 const clock=fakeClock();let calls=0;
 await withRuntime({timers:clock,native:async options=>{
  calls++;options.onHeaders(200,new Headers());await options.onBytes(frame(created));
  clock.tick(3600000);assert.equal(options.signal.aborted,false);
  await options.onBytes(frame(terminal('completed')));
  return {evidence:{terminal_status:'completed'},result:{}};
 }},async post=>{
  assert.equal((await post({...payload,stream_idle_timeout_ms:0})).status,200);
  for(const value of [-1,Infinity,'180000',2147483648])assert.equal((await post({...payload,stream_idle_timeout_ms:value})).status,400);
 });
 assert.equal(calls,1);assert.equal(clock.pending,0);
});

test('client disconnect cancels native reading and releases the session for a subsequent turn',{timeout:5000},async()=>{
 let cancelled,first=true;const upstreamCancelled=new Promise(resolve=>cancelled=resolve);
 const native=options=>runNative({...options,fetchImpl:async()=>{
  if(!first)return new Response(frame(terminal('completed')),{headers:{'content-type':'text/event-stream'}});
  first=false;let sent=false;
  return new Response(new ReadableStream({pull(controller){if(!sent){sent=true;controller.enqueue(frame(created))}},cancel(){cancelled()}},{highWaterMark:0}),{headers:{'content-type':'text/event-stream'}});
 }});
 await withRuntime({native},async post=>{
  const cancel=new AbortController();const response=await post(payload,cancel.signal);
  const reader=response.body.getReader();await reader.read();cancel.abort();
  await upstreamCancelled;
  // The server observes native cleanup on the next event-loop turn.
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(events(await(await post()).text()).at(-1).type,'response.completed');
 });
});
