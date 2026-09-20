import {createServer} from 'node:http';
import {readFileSync,statSync} from 'node:fs';
import {randomUUID,timingSafeEqual} from 'node:crypto';
import {once} from 'node:events';
import {pathToFileURL} from 'node:url';
import {openaiCodexProvider} from '@earendil-works/pi-ai/providers/openai-codex';
const openaiCodexOAuth=openaiCodexProvider().auth.oauth;
import {runNative,credentialAccount,closeSessions} from './native.mjs';

export function createRuntime({secret,sessionSecret=secret,oauth=openaiCodexOAuth,native=runNative}) {
 if(typeof secret!=='string'||secret.length<32)throw Error('runtime_secret_required');
 const sessions=new Map();let loginActive=false;
 const json=(res,status,value)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(value))};
 const credentials=(value,owner)=>({access_token:value.access,refresh_token:value.refresh,expires_at:Math.floor(value.expires/1000),
  chatgpt_account_id:credentialAccount(value.access),harness_kind:'pi',pi_owner_user_id:String(owner)});
 const server=createServer(async(req,res)=>{
  const supplied=Buffer.from(req.headers.authorization||'');const expected=Buffer.from(`Bearer ${secret}`);
  if(supplied.length!==expected.length||!timingSafeEqual(supplied,expected)){json(res,401,{error:'unauthorized'});return}
  try {
   if(req.method==='GET'&&req.url==='/health'){json(res,200,{status:'ok',adapter:'@earendil-works/pi-ai@0.85.1'});return}
   if(req.method!=='POST'){json(res,404,{error:'not_found'});return}
   const chunks=[];let size=0;
   for await(const chunk of req){size+=chunk.length;if(size>8*1024*1024)throw Error('request_too_large');chunks.push(chunk)}
   const body=JSON.parse(Buffer.concat(chunks));
   if(req.url==='/oauth/start') {
    if(!Number.isSafeInteger(body.owner_id)||body.owner_id<1)throw Error('owner_required');
    if(loginActive){json(res,409,{error:'oauth_login_in_progress'});return}
    loginActive=true;
    const id=randomUUID(),controller=new AbortController();
    let authorize,manual;
    const ready=new Promise(resolve=>authorize=resolve);
    const record={owner:body.owner_id,controller,created:Date.now()};
    record.timeout=setTimeout(()=>{controller.abort();sessions.delete(id)},10*60*1000);record.timeout.unref();
    sessions.set(id,record);
    record.promise=oauth.login({signal:controller.signal,notify(message){if(message.type==='auth_url'){record.url=message.url;authorize()}},
     prompt(info){if(info.type==='select')return Promise.resolve('browser');
      if(info.type==='manual_code')return new Promise((resolve,reject)=>{manual=resolve;info.signal?.addEventListener('abort',()=>reject(Error('cancelled')),{once:true})});
      return Promise.reject(Error('unsupported_oauth_prompt'));
     }}).then(value=>{record.credentials=value}).catch(()=>{record.failed=true;authorize()}).finally(()=>{loginActive=false});
    let readyTimeout;
    await Promise.race([ready,new Promise(resolve=>{readyTimeout=setTimeout(resolve,5000)})]);
    clearTimeout(readyTimeout);
    record.manual=value=>manual?.(value);
    if(!record.url||record.failed){controller.abort();clearTimeout(record.timeout);sessions.delete(id);throw Error('oauth_start_failed')}
    json(res,200,{auth_url:record.url,session_id:id});return;
   }
   if(req.url==='/oauth/complete') {
    const record=sessions.get(body.session_id);
    if(!record||record.owner!==body.owner_id)throw Error('oauth_session_mismatch');
    const url=new URL(body.callback_url);const auth=new URL(record.url);
    if(url.origin!=='http://localhost:1455'||url.pathname!=='/auth/callback'||!url.searchParams.get('code')||url.searchParams.get('state')!==auth.searchParams.get('state'))throw Error('oauth_callback_mismatch');
    record.manual(url.href);await record.promise;
    sessions.delete(body.session_id);clearTimeout(record.timeout);
    if(record.failed||!record.credentials)throw Error('oauth_exchange_failed');
    json(res,200,credentials(record.credentials,record.owner));return;
   }
   if(req.url==='/oauth/refresh') {
    if(!Number.isSafeInteger(body.owner_id)||body.owner_id<1)throw Error('owner_required');
    const value=await oauth.refresh({refresh:body.refresh_token},AbortSignal.timeout(30000));
    if(credentialAccount(value.access)!==body.account_id)throw Error('oauth_account_mismatch');
    json(res,200,credentials(value,body.owner_id));return;
   }
   if(req.url==='/responses') {
    const abort=new AbortController();const timeout=setTimeout(()=>abort.abort(),120000);
    res.on('close',()=>{if(!res.writableFinished)abort.abort()});
    let upstreamStatus=200;const responseHeaders={};
    const headers=()=>{if(!res.headersSent)res.writeHead(upstreamStatus,{...responseHeaders,'content-type':'text/event-stream','cache-control':'no-cache','x-sub2api-runtime':'pi-0.85.1'})};
    try {
     const result=await native({request:body.request,accessToken:body.access_token,accountId:body.account_id,
      ownerId:body.owner_id,credentialId:body.credential_id,sessionId:body.session_id,sessionSecret,
      transport:body.transport||'sse',signal:abort.signal,
      onHeaders(status,headers){upstreamStatus=status;
       for(const name of ['x-request-id','x-codex-turn-state','x-codex-primary-used-percent','x-codex-primary-reset-after-seconds','x-codex-secondary-used-percent','x-codex-secondary-reset-after-seconds']){
        const value=headers?.get(name);if(value)responseHeaders[name]=value;
       }
      },
      async onBytes(bytes){headers();if(!res.write(bytes))await once(res,'drain',{signal:abort.signal})}});
     console.log(JSON.stringify({event:'pi_upstream_audit',owner_id:body.owner_id,credential_id:body.credential_id,
      transport:result.transport,outbound:result.outbound,observation:result.evidence,continuation:result.continuation,
      turn_state_present:!!responseHeaders['x-codex-turn-state'],turn_state_length:responseHeaders['x-codex-turn-state']?.length||0}));
     if(!res.headersSent&&result.evidence.terminal_status!=='completed'){json(res,502,{error:'pi_upstream_failed'});return}
     headers();res.end();
    }finally{clearTimeout(timeout)}
    return;
   }
   json(res,404,{error:'not_found'});
  }catch(error){
   // Deliberately do not echo provider exceptions, callbacks, tokens or payloads.
   const safe=['owner_required','oauth_session_mismatch','oauth_callback_mismatch','oauth_account_mismatch','invalid_responses_request','model_required','input_required','unsupported_pi_tool_type'];
   const code=safe.includes(error.message)?error.message:'pi_runtime_error';
   if(res.headersSent)res.destroy();else json(res,error.message==='pi_session_busy'?409:400,{error:code});
  }
 });
 server.on('close',()=>{for(const record of sessions.values()){clearTimeout(record.timeout);record.controller.abort()}sessions.clear();closeSessions()});
 return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const file=process.env.PI_RUNTIME_SECRET_FILE;
 if(!file||(statSync(file).mode&0o077))throw Error('private_runtime_secret_file_required');
 const secret=readFileSync(file,'utf8').trim();
 createRuntime({secret}).listen(Number(process.env.PORT||8091),process.env.HOST||'127.0.0.1',()=>console.log(JSON.stringify({event:'pi_runtime_ready'})));
}
