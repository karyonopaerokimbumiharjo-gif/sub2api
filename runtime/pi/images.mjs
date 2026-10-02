import {credentialAccount} from './native.mjs';
import {schedulingHeaders,rateLimitMetadata} from './rate-limit.mjs';

// Images is a native Codex endpoint, like compact, rather than an SDK agent
// turn. Fixed endpoints prevent the private bearer from becoming a URL proxy.
export async function forwardImages(body,res,fetchImpl=fetch) {
 if(!Number.isSafeInteger(body.owner_id)||body.owner_id<1||!Number.isSafeInteger(body.credential_id)||body.credential_id<1)throw Error('invalid_pi_image_request');
 if(typeof body.access_token!=='string'||typeof body.account_id!=='string'||credentialAccount(body.access_token)!==body.account_id)throw Error('oauth_account_mismatch');
 if(!['/images/generations','/images/edits'].includes(body.endpoint))throw Error('unsupported_pi_image_endpoint');
 const request=body.request;
 if(!request||typeof request!=='object'||Array.isArray(request)||typeof request.model!=='string'||!request.model.startsWith('gpt-image-')||typeof request.prompt!=='string'||!request.prompt.trim())throw Error('invalid_pi_image_request');
 let upstream;
 try {upstream=await fetchImpl('https://chatgpt.com/backend-api/codex'+body.endpoint,{
  method:'POST',redirect:'error',signal:AbortSignal.timeout(10*60*1000),
  headers:{authorization:`Bearer ${body.access_token}`,'chatgpt-account-id':body.account_id,'content-type':'application/json',accept:request.stream?'text/event-stream':'application/json',originator:'codex_cli_rs','user-agent':'codex_cli_rs/0.157.1',version:'0.157.1'},
  body:JSON.stringify(request)
 })}catch(error){
  const status=['AbortError','TimeoutError'].includes(error?.name)?504:502;
  res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify({error:{type:'upstream_error',code:'pi_image_transport_failed',message:'Pi image upstream unavailable'}}));return;
 }
 const headers=Object.fromEntries(schedulingHeaders.filter(name=>upstream.headers.has(name)).map(name=>[name,upstream.headers.get(name)]));
 if(!upstream.ok){
  const reader=upstream.body?.getReader();let size=0;const chunks=[];
  if(reader){try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384)break;chunks.push(value)}}finally{void reader.cancel().catch(()=>{});reader.releaseLock()}}
  let parsed;try{if(size<=16384)parsed=JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{}
  const allowed=new Set(['model_not_found','invalid_model','unsupported_parameter','image_generation_unavailable','content_policy_violation','moderation_blocked','deactivated_workspace']);
  const rawCode=parsed?.error?.code;
  const error=upstream.status===429?{type:'rate_limit_exceeded',...(rateLimitMetadata(parsed)||{}),message:'Image upstream rate limit reached'}:{type:'upstream_error',code:allowed.has(rawCode)?rawCode:'pi_image_upstream_rejected',message:`Image upstream rejected the request (HTTP ${upstream.status})`};
  if(error.scope==='image')error.param='gpt-image';
  res.writeHead(upstream.status,{...headers,'content-type':'application/json'});res.end(JSON.stringify({error}));return;
 }
 res.writeHead(upstream.status,{...headers,'content-type':upstream.headers.get('content-type')||'application/json','x-sub2api-runtime':'pi-1.0.0'});
 // Keep draining a paid generation when its consumer disconnects.
 for await(const chunk of upstream.body||[]){
  if(!res.destroyed&&!res.writableEnded&&!res.write(chunk)){
   await new Promise(resolve=>{
    const done=()=>{res.off('drain',done);res.off('close',done);res.off('error',done);resolve()};
    res.once('drain',done);res.once('close',done);res.once('error',done);
   });
  }
 }
 if(!res.destroyed&&!res.writableEnded)res.end();
}
