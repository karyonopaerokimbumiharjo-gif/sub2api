import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';

// Docker runs this inside the private runtime container. A healthy process must
// answer its authenticated endpoint; an open TCP port alone is not sufficient.
export async function checkRuntimeHealth({
 secretFile=process.env.PI_RUNTIME_SECRET_FILE,
 port=Number(process.env.PORT||8091),
 fetchImpl=fetch,
}={}) {
 if(!secretFile||!Number.isSafeInteger(port)||port<1||port>65535)return false;
 try {
  const secret=(await readFile(secretFile,'utf8')).trim();
  if(secret.length<32)return false;
  const response=await fetchImpl(`http://127.0.0.1:${port}/health`,{
   headers:{authorization:`Bearer ${secret}`},redirect:'error',signal:AbortSignal.timeout(4000),
  });
  if(response.status!==200)return false;
  const body=await response.json();
  return body.status==='ok'&&body.adapter==='@earendil-works/pi-ai@0.87.1';
 }catch{return false}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 process.exitCode=(await checkRuntimeHealth())?0:1;
}
