import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ResponseObserver, observeResponse} from './response-observer.mjs';
const event = status => `data: ${JSON.stringify({type:`response.${status}`,response:{status,model:'gpt-6-astra'}})}\n\n`;
function inspect(text, {type='text/event-stream',limit=1024,interrupted=false,step=1}={}) {
 const observer=new ResponseObserver(type,limit);const bytes=Buffer.from(text);
 for(let i=0;i<bytes.length;i+=step) observer.feed(bytes.subarray(i,i+step));
 return observer.finish(interrupted);
}
test('complete frames survive every chunk boundary and newline style',()=>{
 for(const newline of ['\n','\r\n','\r']) for(let step=1;step<50;step++)
  assert.equal(inspect(event('completed').replaceAll('\n',newline),{step}).terminal_status,'completed');
 assert.equal(inspect('event: response.completed\ndata: {"type":\ndata: "response.completed"}\n\n').terminal_status,'completed');
});
test('EOF never promotes incomplete frames, DONE, comments or malformed JSON',()=>{
 for(const text of ['',': comment\n\n','data: [DONE]\n\n',event('completed').trimEnd(),event('completed').slice(0,-1),
  'event: response.completed\n\n','data: {bad}\n\n','data: "response.completed"\n\n'])
  assert.equal(inspect(text).terminal_status,'missing_terminal');
});
test('terminal evidence and interruption remain independent and finalization is idempotent',()=>{
 assert.deepEqual([inspect('',{interrupted:true}).terminal_status,inspect('',{interrupted:true}).stream_interrupted],[null,true]);
 assert.equal(inspect(event('completed'),{interrupted:true}).terminal_status,'completed');
 assert.equal(inspect(event('completed'),{interrupted:true}).stream_interrupted,true);
 const o=new ResponseObserver();o.feed(Buffer.from(event('failed')));const result=o.finish();
 assert.strictEqual(o.finish(true),result);
});
test('duplicate terminal is idempotent; terminal and field conflicts are explicit',()=>{
 assert.equal(inspect(event('completed').repeat(2)).terminal_status,'completed');
 assert.equal(inspect(event('completed')+event('failed')).terminal_status,'conflicting');
 assert.equal(inspect('event: response.failed\n'+event('completed')).terminal_status,'conflicting');
 assert.equal(inspect('data: {"type":"response.completed","response":{"status":"incomplete"}}\n\n').terminal_status,'conflicting');
});
test('oversize frames are dropped, memory stays bounded, next frame recovers',()=>{
 const o=new ResponseObserver('text/event-stream',256);
 for(let n=0;n<1000;n++) o.feed(Buffer.alloc(1024,65));
 assert.equal(o.buffer.length,256);assert.equal(o.length,0);
 o.feed(Buffer.from('\n\n'+event('completed')));
 assert.equal(o.finish().terminal_status,'completed');assert.equal(o.result.droppedFrames,1);
 assert.equal(inspect('data: '+JSON.stringify({type:'response.completed',padding:'a'.repeat(300)})+'\n\n',{limit:128}).terminal_status,'missing_terminal');
});
test('ordinary JSON requires top-level object=response and exact status',()=>{
 assert.equal(inspect('{"object":"response","status":"completed"}',{type:'application/json'}).terminal_status,'completed');
 for(const raw of ['{"response":{"status":"completed"}}','[{"object":"response","status":"completed"}]','{"object":"response","status":"COMPLETED"}','{"error":"failed"}'])
  assert.equal(inspect(raw,{type:'application/json'}).terminal_status,'missing_terminal');
});
test('inline observation preserves every byte and handles cancellation and read errors',async()=>{
 const bytes=Buffer.from(': hello\r\n\r\n'+event('completed')+'data: [DONE]\n\n');let report;
 const response=observeResponse(new Response(bytes,{headers:{'content-type':'text/event-stream'}}),r=>report=r);
 assert.deepEqual(Buffer.from(await response.arrayBuffer()),bytes);assert.equal(report.terminal_status,'completed');
 let cancelled=0;
 const source=new ReadableStream({pull(c){c.enqueue(Buffer.from(event('completed')))},cancel(){cancelled++}},{highWaterMark:0});
 const reader=observeResponse(new Response(source,{headers:{'content-type':'text/event-stream'}}),r=>report=r).body.getReader();
 await reader.read();await reader.cancel();assert.equal(cancelled,1);assert.equal(report.stream_interrupted,true);assert.equal(report.terminal_status,'completed');
 const broken=observeResponse(new Response(new ReadableStream({pull(c){c.error(Error('fixture'))}}),{headers:{'content-type':'text/event-stream'}}),r=>report=r);
 await assert.rejects(broken.text());assert.equal(report.terminal_status,null);assert.equal(report.stream_interrupted,true);
});
