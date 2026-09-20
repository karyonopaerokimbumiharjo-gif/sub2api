// Exercise the real, pinned Pi adapter against the existing Sub2API gateway.
// Read a Sub2API API key, never the upstream Codex auth file.
import { readFileSync, statSync } from 'node:fs';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { stream } from '@earendil-works/pi-ai/api/openai-responses';
import { modelAcceptance, requestEvidence } from './acceptance.mjs';
import { observeResponse } from './response-observer.mjs';

const keyFile = process.env.SUB2API_KEY_FILE;
if (!keyFile || (statSync(keyFile).mode & 0o077)) throw Error('Set SUB2API_KEY_FILE to a private key file');
const apiKey = readFileSync(keyFile,'utf8').trim();
const baseUrl = process.env.SUB2API_BASE_URL || 'http://127.0.0.1:8080/v1';
const url = new URL(baseUrl);
if (url.hostname !== '127.0.0.1' && url.protocol !== 'https:') throw Error('Use HTTPS or literal loopback');
const model = { id: process.env.SUB2API_MODEL || 'gpt-6-astra', name:'Sub2API', api:'openai-responses', provider:'sub2api', baseUrl,
 reasoning:true, input:['text'], cost:{input:0,output:0,cacheRead:0,cacheWrite:0}, contextWindow:128000,maxTokens:1024 };
const sessionId=randomUUID();
const context={systemPrompt:'You are verifying a tool integration. Follow the user request exactly.',messages:[
 {role:'user',content:'Call integration_echo once with value PI_SUB2API_OK. After the tool result, reply with its exact text only.',timestamp:Date.now()}
],tools:[{name:'integration_echo',description:'Return the verification value.',parameters:{type:'object',properties:{value:{type:'string'}},required:['value'],additionalProperties:false}}]};
let requests=0;
const modelChecks=[];
async function run(extra={}) {
 const counts={}; let httpStatus=0; let requestedModel; let ingress;
 let observed;
 let resolveObservation;
 const observation=new Promise(resolve=>{resolveObservation=resolve});
 const observeFetch=async (input,init)=>{
  ingress=requestEvidence(init?.headers, JSON.parse(init.body));
  let response;
  try { response=await fetch(input,init); } catch(error) { resolveObservation(); throw error; }
  return observeResponse(response,result=>{observed=result;resolveObservation()});
 };
 const response=stream(model,context,{apiKey,sessionId,maxRetries:0,timeoutMs:90000,signal:AbortSignal.timeout(95000),reasoningEffort:'low',
 fetch:observeFetch,onPayload:body=>{requestedModel=body.model},onResponse:r=>{httpStatus=r.status},...extra}); requests++;
 for await(const event of response) counts[event.type]=(counts[event.type]||0)+1;
 const result=await response.result();
 if (['error','aborted'].includes(result.stopReason) && !observed) throw Error('Pi request did not complete');
 await observation;
 // Do not log provider errors or message contents: errors can echo request data.
 const acceptance=modelAcceptance(new Set(observed.observedModels),model.id,process.env.SUB2API_EXPECT_MODELS);
 modelChecks.push(acceptance);
 console.log(JSON.stringify({request:requests,httpStatus,requestedModel,stopReason:result.stopReason,events:counts,ingress,observation:observed,modelAcceptance:acceptance}));
 assert.equal(httpStatus,200,'Expected HTTP 200');
 assert.equal(requestedModel,model.id,'Requested model was changed before sending');
 assert.equal(observed.terminal_status,'completed','Expected a complete SSE terminal frame');
 assert.equal(observed.stream_interrupted,false,'Stream was interrupted');
 assert.equal(observed.modelOverflow,false,'Too many model declarations');
 assert.ok(!['error','aborted','pending','length'].includes(result.stopReason),'Pi did not complete successfully');
 return result;
}
const first=await run({toolChoice:{type:'function',name:'integration_echo'}});
const calls=first.content.filter(x=>x.type==='toolCall');
assert.equal(calls.length,1,'Expected one tool call');
assert.equal(calls[0].name,'integration_echo');assert.equal(calls[0].arguments.value,'PI_SUB2API_OK');
context.messages.push(first,{role:'toolResult',toolCallId:calls[0].id,toolName:calls[0].name,content:[{type:'text',text:'PI_SUB2API_OK'}],isError:false,timestamp:Date.now()});
const second=await run({toolChoice:'none'});
assert.equal(second.content.filter(x=>x.type==='text').map(x=>x.text).join('').trim(),'PI_SUB2API_OK');
const modelPassed=modelChecks.every(check=>check.passed);
console.log(JSON.stringify({result:modelPassed?'PASS':'FAIL',protocolPassed:true,modelPassed,adapter:'@earendil-works/pi-ai@0.85.1',verified:['SSE completion','tool call arguments','tool result continuation','final text'],requests}));
if(!modelPassed) process.exitCode=1;
