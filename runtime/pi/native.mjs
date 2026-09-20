import {AsyncLocalStorage} from 'node:async_hooks';
import {createHmac} from 'node:crypto';
import {zstdDecompressSync} from 'node:zlib';
import WebSocket from 'ws';
import {stream, getOpenAICodexWebSocketDebugStats, closeOpenAICodexWebSocketSessions} from '@earendil-works/pi-ai/api/openai-codex-responses';
import {ResponseObserver} from '../../tools/pi-integration/response-observer.mjs';
import {requestEvidence} from '../../tools/pi-integration/acceptance.mjs';

const active = new AsyncLocalStorage();
const inFlight = new Set();
// Pi explicitly uses globalThis.WebSocket as its runtime transport extension point.
// The socket's request owner is updated on send, including reused connections.
class ObservedWebSocket extends WebSocket {
 constructor(url, options) {
  super(url,{...options,maxPayload:4*1024*1024,perMessageDeflate:false});
  this.requestHeaders=options?.headers;
  this.on('message',bytes=>{
   if(!this.owner?.active)return;
   const frame=Buffer.concat([Buffer.from('data: '),Buffer.from(bytes),Buffer.from('\n\n')]);
   const owner=this.owner;
   owner.observer.feed(frame);
   this.pause();
   owner.pending=owner.pending.then(()=>owner.onBytes(frame)).catch(()=>{
    owner.deliveryFailed=true;
    this.terminate();
   }).finally(()=>{if(this.readyState===WebSocket.OPEN)this.resume()});
  });
 }
 send(data,...args) {
  this.owner=active.getStore();
  if(this.owner) {
   const body=JSON.parse(data);
   this.owner.outbound=requestEvidence(this.requestHeaders,body);
   this.owner.transport='websocket';
  }
  return super.send(data,...args);
 }
}
globalThis.WebSocket=ObservedWebSocket;

export function credentialAccount(access) {
 try {
  const claims=JSON.parse(Buffer.from(access.split('.')[1],'base64url'));
  const account=claims['https://api.openai.com/auth']?.chatgpt_account_id;
  if(typeof account==='string'&&account.length>0)return account;
 }catch{}
 throw Error('invalid_oauth_account');
}
export function scopedSession(secret,owner,credential,account,model,session) {
 if(!owner||!credential||!account||!session)throw Error('missing_session_binding');
 return createHmac('sha256',secret).update(JSON.stringify([owner,credential,account,model,session])).digest('hex');
}
const allowed=new Set(['model','instructions','input','tools','tool_choice','parallel_tool_calls','reasoning','service_tier','text','include','stream','store']);
export function nativeBody(request,defaults) {
 if(!request||typeof request!=='object'||Array.isArray(request))throw Error('invalid_responses_request');
 for(const key of Object.keys(request))if(!allowed.has(key))throw Error(`unsupported_pi_field:${key}`);
 if(typeof request.model!=='string'||!request.model)throw Error('model_required');
 if(!Array.isArray(request.input)&&typeof request.input!=='string')throw Error('input_required');
 if(request.tools?.some(tool=>tool.type!=='function'))throw Error('unsupported_pi_tool_type');
 const input=typeof request.input==='string'?[{role:'user',content:[{type:'input_text',text:request.input}]}]:request.input;
 return {...defaults,...structuredClone(request),input:structuredClone(input),store:false,stream:true,
  instructions:request.instructions||defaults.instructions,
  include:[...new Set(['reasoning.encrypted_content',...(request.include||[])])],
  prompt_cache_key:defaults.prompt_cache_key};
}
export async function runNative({request,accessToken,accountId,ownerId,credentialId,sessionId,sessionSecret,
 transport='sse',signal,onBytes,onHeaders=()=>{},baseUrl='https://chatgpt.com/backend-api',fetchImpl=fetch}) {
 if(credentialAccount(accessToken)!==accountId)throw Error('oauth_account_mismatch');
 if(!['auto','sse','websocket','websocket-cached'].includes(transport))throw Error('invalid_transport');
 const scoped=scopedSession(sessionSecret,ownerId,credentialId,accountId,request.model,sessionId);
 // Validate before any credentials leave the process.
 nativeBody(request,{instructions:'You are a helpful assistant.'});
 if(inFlight.has(scoped))throw Error('pi_session_busy');
 inFlight.add(scoped);
 const observer=new ResponseObserver();
 const state={active:true,observer,onBytes,outbound:null,transport:null,pending:Promise.resolve(),deliveryFailed:false,sseEOF:false,transportInterrupted:false};
 const model={id:request.model,name:request.model,provider:'openai-codex',api:'openai-codex-responses',baseUrl,
  reasoning:true,input:['text','image'],cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:128000,maxTokens:4096};
 let result;
 try {
  await active.run(state,async()=>{
   const response=stream(model,{systemPrompt:request.instructions||'You are a helpful assistant.',messages:[]},
    {apiKey:accessToken,sessionId:scoped,transport,signal,maxRetries:0,timeoutMs:90000,websocketConnectTimeoutMs:15000,
     onPayload:defaults=>nativeBody(request,defaults),
     fetch:async(url,init)=>{
      // Native SDK has constructed the headers; inspect only redacted evidence.
      const headers=new Headers(init.headers);
      const body=headers.get('content-encoding')==='zstd'?zstdDecompressSync(init.body,{maxOutputLength:8*1024*1024}).toString():init.body;
      state.outbound=requestEvidence(headers,JSON.parse(body));
      state.transport='sse';
      const upstream=await fetchImpl(url,{...init,redirect:'error'});
      onHeaders(upstream.status,upstream.headers);
      if(!upstream.ok)return upstream;
      const reader=upstream.body.getReader();
      return new Response(new ReadableStream({async pull(controller){
       try{const {done,value}=await reader.read();if(done){state.sseEOF=true;controller.close();return}
        observer.feed(value);await onBytes(value);controller.enqueue(value);
       }catch(error){state.transportInterrupted=true;controller.error(error)}
      },async cancel(reason){if(!state.sseEOF)state.transportInterrupted=true;await reader.cancel(reason)}},{highWaterMark:0}),{status:upstream.status,headers:upstream.headers});
     }});
   for await(const _event of response){/* SDK owns parsing and continuation state. */}
   result=await response.result();
  });
  await state.pending;
  const interrupted=state.transportInterrupted||state.deliveryFailed||signal?.aborted===true||['error','aborted'].includes(result.stopReason);
  const evidence=observer.finish(interrupted);
  const stats=getOpenAICodexWebSocketDebugStats(scoped);
  return {result,evidence,outbound:state.outbound,transport:state.transport,
   continuation:stats?{connectionsCreated:stats.connectionsCreated,connectionsReused:stats.connectionsReused,
    deltaRequests:stats.deltaRequests,fullContextRequests:stats.fullContextRequests,sseFallbacks:stats.sseFallbacks}:null};
 }finally{state.active=false;inFlight.delete(scoped)}
}
export function closeSessions(){closeOpenAICodexWebSocketSessions()}
