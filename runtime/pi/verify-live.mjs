// Explicit opt-in live acceptance. Credentials are read locally and never logged.
import {readFileSync,statSync} from 'node:fs';
import {randomBytes,randomUUID} from 'node:crypto';
import {runNative,credentialAccount,closeSessions} from './native.mjs';
import {convertResponsesMessages} from '@earendil-works/pi-ai/api/openai-responses-shared';
import {modelAcceptance} from '../../tools/pi-integration/acceptance.mjs';
const file=process.env.PI_AUTH_FILE;
if(!file||(statSync(file).mode&0o077))throw Error('PI_AUTH_FILE must be a private OAuth file');
const auth=JSON.parse(readFileSync(file,'utf8'));
const accessToken=auth.tokens?.access_token||auth.access_token;
const accountId=credentialAccount(accessToken);
const model=process.env.SUB2API_MODEL||'gpt-6-astra';
const transport=process.env.PI_TRANSPORT||'sse';
const sessionId=randomUUID(),sessionSecret=randomBytes(32).toString('hex');
const input=[{role:'user',content:[{type:'input_text',text:'Call integration_echo once with value PI_NATIVE_OK. Then repeat the tool result exactly.'}]}];
const tool={type:'function',name:'integration_echo',description:'Echo verification text.',parameters:{type:'object',properties:{value:{type:'string'}},required:['value'],additionalProperties:false}};
let passed=true;
async function run(turn,request){
 let chunks=[],size=0,status=0;
 const result=await runNative({request,accessToken,accountId,ownerId:1,credentialId:'local-auth-live-test',sessionId,sessionSecret,transport,
 signal:AbortSignal.timeout(100000),onHeaders:s=>status=s,onBytes:bytes=>{size+=bytes.length;if(size>2*1024*1024)throw Error('verification_response_limit');chunks.push(Buffer.from(bytes))}});
 const acceptance=modelAcceptance(new Set(result.evidence.observedModels),model,process.env.SUB2API_EXPECT_MODELS);
 const protocolPassed=result.evidence.terminal_status==='completed'&&!['error','aborted'].includes(result.result.stopReason);
 passed&&=protocolPassed&&acceptance.passed;
 console.log(JSON.stringify({turn,requestedModel:model,httpStatus:status||null,transport:result.transport,observation:result.evidence,outbound:result.outbound,continuation:result.continuation,modelAcceptance:acceptance,protocolPassed}));
 if(!protocolPassed)throw Error('native_protocol_failed');
 const frames=Buffer.concat(chunks).toString().replace(/\r\n/g,'\n').split('\n\n');
 let response;const output=[];
 for(const frame of frames){try{const value=JSON.parse(frame.split('\n').filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n'));if(value.type==='response.output_item.done'&&value.item)output.push(value.item);if(value.type==='response.completed')response=value.response}catch{}}
 if(!response)throw Error('terminal_response_missing');
 return {...response,replayItems:convertResponsesMessages({id:model,provider:'openai-codex',api:'openai-codex-responses'},{messages:[result.result]},new Set(['openai','openai-codex','opencode']),{includeSystemPrompt:false}),output:response.output?.length?response.output:output};
}
try{
 const first=await run(1,{model,input,tools:[tool],tool_choice:'auto',reasoning:{effort:'low'}});
 const calls=first.output.filter(item=>item.type==='function_call');
 console.log(JSON.stringify({toolCallCount:calls.length,expectedToolName:calls[0]?.name==='integration_echo',outputItemTypes:first.output.map(item=>['function_call','message','reasoning'].includes(item.type)?item.type:'other')}));
 if(calls.length!==1||calls[0].name!=='integration_echo'||JSON.parse(calls[0].arguments).value!=='PI_NATIVE_OK')throw Error('tool_call_mismatch');
 input.push(...first.replayItems,{type:'function_call_output',call_id:calls[0].call_id,output:'PI_NATIVE_OK'});
 const second=await run(2,{model,input,tools:[tool],tool_choice:'auto',reasoning:{effort:'low'}});
 const text=second.output.filter(item=>item.type==='message').flatMap(item=>item.content||[]).filter(item=>item.type==='output_text').map(item=>item.text).join('').trim();
 if(text!=='PI_NATIVE_OK')throw Error('tool_result_mismatch');
 console.log(JSON.stringify({result:passed?'PASS':'FAIL',toolContinuationPassed:true,modelPassed:passed}));
 process.exitCode=passed?0:1;
}catch(error){const reasons=['native_protocol_failed','terminal_response_missing','tool_call_mismatch','tool_result_mismatch','verification_response_limit'];console.log(JSON.stringify({result:'FAIL',reason:reasons.includes(error.message)?error.message:'native_acceptance_failed'}));process.exitCode=1}
finally{closeSessions()}
