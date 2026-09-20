// Direct pinned SDK baseline: no native.mjs import, onPayload, custom WS,
// gateway, or request-header/body rewriting. The fetch observer only reads.
import {readFileSync,statSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {zstdDecompressSync} from 'node:zlib';
import {stream} from '@earendil-works/pi-ai/api/openai-codex-responses';
import {ResponseObserver} from '../../tools/pi-integration/response-observer.mjs';
import {modelAcceptance} from '../../tools/pi-integration/acceptance.mjs';

const file=process.env.PI_AUTH_FILE;
if(!file||(statSync(file).mode&0o077))throw Error('PI_AUTH_FILE must be private');
const auth=JSON.parse(readFileSync(file,'utf8'));
const access=auth.tokens?.access_token||auth.access_token;
if(!access)throw Error('OAuth access token required');
const model=process.env.SUB2API_MODEL||'gpt-6-astra';
const definition={id:model,name:model,provider:'openai-codex',api:'openai-codex-responses',
 baseUrl:'https://chatgpt.com/backend-api',reasoning:true,input:['text','image'],
 cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:128000,maxTokens:4096};
const context={systemPrompt:'Follow the user request exactly.',messages:[
 {role:'user',content:'Reply with exactly PI_DIRECT_OK. Do not call tools.',timestamp:Date.now()}
]};
let observation,requestEvidence,httpStatus,eof=false;
const observer=new ResponseObserver();
try {
 const response=stream(definition,context,{apiKey:access,sessionId:randomUUID(),transport:'sse',
  reasoningEffort:'low',maxRetries:0,signal:AbortSignal.timeout(100000),
  fetch:async(url,init)=>{
   const headers=new Headers(init.headers);
   const body=JSON.parse(headers.get('content-encoding')==='zstd'?zstdDecompressSync(init.body).toString():init.body);
   requestEvidence={officialEndpoint:new URL(url).origin==='https://chatgpt.com',
    modelMatchesRequest:body.model===model,originatorIsPi:headers.get('originator')==='pi',
    accountHeaderPresent:headers.has('chatgpt-account-id'),inputItemCount:body.input?.length};
   const upstream=await fetch(url,init);httpStatus=upstream.status;
   if(!upstream.ok)return upstream;
   const reader=upstream.body.getReader();
   return new Response(new ReadableStream({async pull(controller){
    try{const next=await reader.read();if(next.done){eof=true;controller.close();return}
     observer.feed(next.value);controller.enqueue(next.value);
    }catch(error){controller.error(error)}
   },cancel:reason=>reader.cancel(reason)},{highWaterMark:0}),{status:upstream.status,headers:upstream.headers});
  }});
 for await(const _event of response){}
 const result=await response.result();observation=observer.finish(!eof);
 const acceptance=modelAcceptance(new Set(observation.observedModels),model);
 const text=result.content.filter(item=>item.type==='text').map(item=>item.text).join('').trim();
 const protocolPassed=httpStatus===200&&observation.terminal_status==='completed'&&result.stopReason==='stop'&&text==='PI_DIRECT_OK';
 console.log(JSON.stringify({baseline:'unwrapped-pi-sdk',version:'0.85.1',timestamp:new Date().toISOString(),
  requestedModel:model,transport:'sse',httpStatus,requestEvidence,observation,protocolPassed,modelAcceptance:acceptance}));
 process.exitCode=protocolPassed&&acceptance.passed?0:1;
}catch{
 console.log(JSON.stringify({baseline:'unwrapped-pi-sdk',requestedModel:model,httpStatus:httpStatus||null,
  requestEvidence,observation:observation||observer.finish(true),result:'FAIL'}));process.exitCode=1;
}
