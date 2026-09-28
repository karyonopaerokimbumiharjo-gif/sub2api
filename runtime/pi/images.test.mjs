import {test} from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {zstdDecompressSync} from 'node:zlib';
import {createRuntime} from './server.mjs';
import {runNative} from './native.mjs';

const secret='s'.repeat(40);
const token=account=>`test.${Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:account}})).toString('base64url')}.test`;
const png='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jY1sAAAAASUVORK5CYII=';
const binding={owner_id:1,credential_id:7,account_id:'account-a',access_token:token('account-a')};

test('Pi Images forwards exact models, edits and output bytes through the bound credential',async()=>{
 const calls=[];
 const server=createRuntime({secret,imageFetch:async(url,init)=>{
  const request=JSON.parse(init.body);calls.push({url,request});
  assert.equal(init.headers.authorization,`Bearer ${binding.access_token}`);
  assert.equal(init.headers['chatgpt-account-id'],'account-a');
  const result=JSON.stringify({created:1,model:request.model,data:[{b64_json:png}],usage:{input_tokens:3,output_tokens:2}});
  return new Response(request.stream?`data: ${result}\n\n`:result,{headers:{'content-type':request.stream?'text/event-stream':'application/json','x-request-id':'image-fixture','set-cookie':'never-forward'}});
 }});
 server.listen(0,'127.0.0.1');await once(server,'listening');
 try{
  for(const endpoint of ['/images/generations','/images/edits'])for(const stream of [false,true]){
   const request={model:'gpt-image-2.5-sunburst',prompt:'A blue circle.',size:'1024x1024',quality:'low',stream,...(endpoint.endsWith('edits')?{images:[{image_url:`data:image/png;base64,${png}`}]}:{})};
   const response=await fetch(`http://127.0.0.1:${server.address().port}/images`,{method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},body:JSON.stringify({...binding,endpoint,request})});
   assert.equal(response.status,200);assert.equal(response.headers.has('set-cookie'),false);
   assert.ok((await response.text()).includes(png));
   assert.deepEqual(calls.at(-1),{url:'https://chatgpt.com/backend-api/codex'+endpoint,request});
  }
  for(const override of [{endpoint:'https://other.invalid/'},{account_id:'other-account'},{owner_id:0},{credential_id:0}]){
   const response=await fetch(`http://127.0.0.1:${server.address().port}/images`,{method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},body:JSON.stringify({...binding,endpoint:'/images/generations',request:{model:'gpt-image-2',prompt:'circle'},...override})});
   assert.equal(response.status,400);
  }
  assert.equal(calls.length,4);
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
});

test('Pi image quota errors preserve reset evidence without provider content',async()=>{
 const server=createRuntime({secret,imageFetch:async()=>new Response(JSON.stringify({error:{type:'usage_limit_reached',resets_in_seconds:120,message:'private provider text'}}),{status:429,headers:{'retry-after':'120'}})});
 server.listen(0,'127.0.0.1');await once(server,'listening');
 try{
  const response=await fetch(`http://127.0.0.1:${server.address().port}/images`,{method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},body:JSON.stringify({...binding,endpoint:'/images/generations',request:{model:'gpt-image-2',prompt:'circle'}})});
  assert.equal(response.status,429);assert.equal(response.headers.get('retry-after'),'120');
  assert.deepEqual(await response.json(),{error:{type:'usage_limit_reached',resets_in_seconds:120,message:'Image upstream rate limit reached'}});
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
});

test('native SDK preserves image_generation tools and completed image output',async()=>{
 const request={model:'gpt-5.5',input:'Draw a blue circle.',tools:[{type:'image_generation',model:'gpt-image-2',quality:'low',size:'1024x1024'}],tool_choice:{type:'image_generation'}};
 const chunks=[];
 const terminal={type:'response.completed',response:{id:'resp_image',status:'completed',model:'gpt-5.5',output:[{type:'image_generation_call',id:'ig_fixture',status:'completed',result:png}],usage:{input_tokens:3,output_tokens:2}}};
 const result=await runNative({request,ownerId:1,credentialId:7,accountId:'account-a',accessToken:binding.access_token,sessionId:'image-sdk',sessionSecret:secret,transport:'sse',onBytes:bytes=>chunks.push(Buffer.from(bytes)),fetchImpl:async(_url,init)=>{
  const headers=new Headers(init.headers);
  const payload=JSON.parse(headers.get('content-encoding')==='zstd'?zstdDecompressSync(init.body).toString():init.body);
  assert.deepEqual(payload.tools,request.tools);assert.deepEqual(payload.tool_choice,request.tool_choice);
  assert.equal(payload.model,'gpt-5.5');
  return new Response(`data: ${JSON.stringify(terminal)}\n\n`,{headers:{'content-type':'text/event-stream'}});
 }});
 assert.equal(result.evidence.terminal_status,'completed');
 assert.equal(Buffer.concat(chunks).toString(),`data: ${JSON.stringify(terminal)}\n\n`);
});
