import {test} from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {createRuntime,validateCodexAccess} from './server.mjs';

const jwt=account=>`e30.${Buffer.from(JSON.stringify({'https://api.openai.com/auth':{chatgpt_account_id:account}})).toString('base64url')}.test`;

test('read-only Pi access check uses only the fixed official models endpoint',async()=>{
 let requested;
 const result=await validateCodexAccess({accessToken:jwt('account-a'),accountId:'account-a',fetchImpl:async(url,init)=>{
  requested={url,init};return new Response(JSON.stringify({models:[{slug:'gpt-6-astra'}]}),{status:200,headers:{'content-type':'application/json'}});
 }});
 assert.equal(result,'account-a');
 assert.equal(requested.url,'https://chatgpt.com/backend-api/codex/models?client_version=0.144.0');
 assert.equal(requested.init.method,'GET');
 assert.equal(requested.init.redirect,'error');
 assert.equal(requested.init.headers['chatgpt-account-id'],'account-a');
 assert.equal(requested.init.headers.authorization,`Bearer ${jwt('account-a')}`);
});

test('read-only Pi access check rejects wrong identity, 401 and non-manifest responses',async()=>{
 let called=false;
 await assert.rejects(validateCodexAccess({accessToken:jwt('account-a'),accountId:'account-b',fetchImpl:()=>{called=true}}),/oauth_account_mismatch/);
 assert.equal(called,false);
 await assert.rejects(validateCodexAccess({accessToken:jwt('account-a'),accountId:'account-a',fetchImpl:async()=>new Response('{}',{status:401})}),/oauth_access_rejected/);
 await assert.rejects(validateCodexAccess({accessToken:jwt('account-a'),accountId:'account-a',fetchImpl:async()=>new Response('{}',{status:200})}),/oauth_access_invalid_response/);
});

test('Pi auth import validation never refreshes or returns a token',async()=>{
 const secret='s'.repeat(40);
 let refreshes=0,verifications=0;
 const runtime=createRuntime({secret,oauth:{async refresh(){refreshes++;throw Error('must not refresh')}},verifyAccess:async({accountId,accessToken})=>{
  verifications++;
  assert.equal(accountId,'account-a');
  assert.equal(accessToken,jwt('account-a'));
  return accountId;
 }});
 runtime.listen(0,'127.0.0.1');await once(runtime,'listening');
 try{
  const response=await fetch(`http://127.0.0.1:${runtime.address().port}/oauth/validate`,{
   method:'POST',headers:{authorization:`Bearer ${secret}`,'content-type':'application/json'},
   body:JSON.stringify({owner_id:7,account_id:'account-a',access_token:jwt('account-a')})
  });
  assert.equal(response.status,200);
  const body=await response.json();
  assert.deepEqual(body,{chatgpt_account_id:'account-a',harness_kind:'pi',pi_owner_user_id:'7'});
  assert.equal(JSON.stringify(body).includes(jwt('account-a')),false);
  assert.equal(refreshes,0);
  assert.equal(verifications,1);
 }finally{runtime.closeAllConnections();await new Promise(resolve=>runtime.close(resolve))}
});
