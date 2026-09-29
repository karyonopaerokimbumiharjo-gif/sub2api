import {test} from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {request as httpRequest} from 'node:http';
import {zstdDecompressSync} from 'node:zlib';
import {createRuntime} from './server.mjs';
import {runNative} from './native.mjs';

const secret='s'.repeat(40);
const accessToken=`test.${Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:'account-a'}})).toString('base64url')}.test`;
const binding={owner_id:1,credential_id:52,session_id:'large-tool-history',account_id:'account-a',access_token:accessToken};
const terminal={type:'response.completed',response:{id:'resp_large_history',object:'response',status:'completed',model:'gpt-6-sol',output:[],usage:{input_tokens:1,output_tokens:0,total_tokens:1}}};
const frames=`data: ${JSON.stringify(terminal)}\n\n`;
function toolHistory() {
 const input=[{role:'user',content:'Review these harmless interface fixtures.'}];
 for(let i=0;i<86;i++)input.push(
  {type:'function_call',call_id:`call_fixture_${i}`,name:'computer_click',arguments:'{"target":"fixture"}'},
  {type:'function_call_output',call_id:`call_fixture_${i}`,output:'ordinary fixture '.repeat(6400)});
 return {model:'gpt-6-sol',input,tools:[{type:'function',name:'computer_click',parameters:{type:'object',properties:{target:{type:'string'}}}}]};
}
async function withRuntime(options,check) {
 const server=createRuntime({secret,...options});server.listen(0,'127.0.0.1');await once(server,'listening');
 const root=`http://127.0.0.1:${server.address().port}`;
 const post=(path,body)=>fetch(root+path,{method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},body:JSON.stringify(body)});
 try{return await check(post,root)}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
}
function inspectOutbound(init,expected) {
 const headers=new Headers(init.headers);
 const raw=headers.get('content-encoding')==='zstd'?zstdDecompressSync(init.body).toString():init.body;
 assert.ok(Buffer.byteLength(raw)>8*1024*1024);
 assert.deepEqual(JSON.parse(raw).input,expected.input);
}
test('Responses forwards an intact tool history above 8 MiB through the real Pi SDK',async()=>{
 const request=toolHistory();let calls=0;
 await withRuntime({native:options=>runNative({...options,fetchImpl:async(_url,init)=>{
  calls++;inspectOutbound(init,request);return new Response(frames,{headers:{'content-type':'text/event-stream'}});
 }})},async post=>{
  const response=await post('/responses',{...binding,request});
  assert.equal(response.status,200);assert.equal(await response.text(),frames);assert.equal(calls,1);
 });
});
test('native SDK compression observation does not impose a second 8 MiB cap',async()=>{
 const request=toolHistory();let calls=0;
 const result=await runNative({request,accessToken,accountId:'account-a',ownerId:1,credentialId:52,sessionId:'large-sdk',sessionSecret:secret,transport:'sse',onBytes:()=>{},fetchImpl:async(_url,init)=>{
  calls++;inspectOutbound(init,request);return new Response(frames,{headers:{'content-type':'text/event-stream'}});
 }});
 assert.equal(calls,1);assert.equal(result.evidence.terminal_status,'completed');
});
test('compact accepts the same long tool history without truncation',async()=>{
 const request=toolHistory();let calls=0;
 await withRuntime({compactFetch:async(_url,init)=>{
  calls++;assert.deepEqual(JSON.parse(init.body).input,request.input);
  return new Response('{"object":"response.compaction","output":[]}',{headers:{'content-type':'application/json'}});
 }},async post=>{
  const response=await post('/compact',{...binding,request});assert.equal(response.status,200);assert.equal((await response.json()).object,'response.compaction');assert.equal(calls,1);
 });
});
test('oversized declared and chunked bodies return 413 without contacting a provider',async()=>{
 let calls=0;
 await withRuntime({maxRequestBodyBytes:1024,native:async()=>{calls++;throw Error('must not call provider')},compactFetch:async()=>{calls++},imageFetch:async()=>{calls++}},async(post,root)=>{
  for(const path of ['/responses','/compact','/images']){
   const response=await post(path,{request:{model:'gpt-6-sol',input:'x'.repeat(2048)}});
   assert.equal(response.status,413);assert.deepEqual(await response.json(),{error:'request_too_large'});
  }
  const result=await new Promise((resolve,reject)=>{
   const req=httpRequest(root+'/responses',{method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json','transfer-encoding':'chunked'}},res=>{
    const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString()}));
   });
   req.on('error',reject);req.write('x'.repeat(512));req.end('x'.repeat(1024));
  });
  assert.equal(result.status,413);assert.deepEqual(JSON.parse(result.body),{error:'request_too_large'});assert.equal(calls,0);
 });
});
test('malformed JSON and internal exceptions have distinct safe error statuses',async()=>{
 await withRuntime({native:async()=>{throw Error('private-payload-must-not-leak')}},async(post,root)=>{
  const malformed=await fetch(root+'/responses',{method:'POST',headers:{authorization:`Bearer ${secret}`},body:'{"private-payload-must-not-leak":'});
  assert.equal(malformed.status,400);assert.deepEqual(await malformed.json(),{error:'invalid_responses_request'});
  const failed=await post('/responses',{...binding,request:{model:'gpt-6-sol',input:'fixture'}});
  assert.equal(failed.status,502);assert.deepEqual(await failed.json(),{error:'pi_runtime_error'});
 });
});
