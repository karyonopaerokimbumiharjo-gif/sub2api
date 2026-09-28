// Only scheduling evidence crosses the private runtime boundary. Never forward
// provider messages, echoed prompts, cookies or credentials with a quota error.
export const schedulingHeaders=['x-request-id','retry-after','x-codex-primary-used-percent','x-codex-primary-window-minutes','x-codex-primary-reset-after-seconds','x-codex-secondary-used-percent','x-codex-secondary-window-minutes','x-codex-secondary-reset-after-seconds','x-ratelimit-reset-requests','x-ratelimit-reset-tokens'];

export function rateLimitMetadata(value) {
 const error=value?.error;
 if(!error||typeof error!=='object')return undefined;
 const imageScope=/gpt-image|input-images per min/i.test(String(error.message||'')+' '+String(error.code||''));
 const knownType=['usage_limit_reached','rate_limit_exceeded'].includes(error.type);
 if(!knownType&&!imageScope)return undefined;
 const result={type:knownType?error.type:'rate_limit_exceeded'};
 // Preserve only a bounded scope marker; the original gateway distinguishes
 // image quota from text quota without forwarding provider error messages.
 if(imageScope)result.scope='image';
 for(const name of ['resets_at','resets_in_seconds']){
  const raw=error[name];
  const number=typeof raw==='number'?raw:typeof raw==='string'&&/^\d+$/.test(raw)?Number(raw):NaN;
  if(Number.isSafeInteger(number)&&number>0)result[name]=number;
 }
 return Object.keys(result).length>1?result:undefined;
}

export async function readRateLimitMetadata(response) {
 if(response.status!==429||!response.body)return undefined;
 const reader=response.clone().body.getReader();
 const chunks=[];let size=0;
 try {
  while(true){
   const {done,value}=await reader.read();if(done)break;
   size+=value.length;if(size>16384)return undefined;
   chunks.push(value);
  }
  return rateLimitMetadata(JSON.parse(Buffer.concat(chunks).toString('utf8')));
 }catch{return undefined}
 finally {
  // A tee branch's cancellation may wait for the SDK to consume the original.
  void reader.cancel().catch(()=>{});
  reader.releaseLock();
 }
}
