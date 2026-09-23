import { lstat, realpath, mkdir, readFile, writeFile, chmod, unlink, rename, rmdir } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { homedir } from 'node:os'
import { createHash, randomUUID } from 'node:crypto'

const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const maxBytes = 32 * 1024 * 1024
export function validateRollbackFiles(files) {
  if (!Array.isArray(files) || !files.length || files.length > 64 || new Set(files).size !== files.length || files.some(file => typeof file !== 'string' || !file || isAbsolute(file) || file.split(/[\\/]/).some(part => !part || part === '.' || part === '..'))) throw Error('rollback_files_required')
}
async function target(workspace, file) {
  const path = resolve(workspace, file)
  const rel = relative(workspace, path)
  if (!rel || rel.startsWith('..' + sep) || isAbsolute(rel)) throw Error('snapshot_path_escape')
  // Existing parent directories are required. Never follow a tool-created symlink.
  if (await realpath(dirname(path)) !== dirname(path)) throw Error('snapshot_symlink_rejected')
  let stat
  try { stat = await lstat(path) } catch (error) { if (error.code !== 'ENOENT') throw error }
  if (stat && (!stat.isFile() || stat.nlink !== 1 || stat.size > maxBytes)) throw Error('snapshot_unsafe_file')
  return { path, stat }
}
async function fingerprint(workspace, file) {
  const { path, stat } = await target(workspace, file)
  if (!stat) return { exists:false }
  const bytes = await readFile(path)
  if (bytes.length > maxBytes) throw Error('snapshot_too_large')
  return { exists:true, sha256:hash(bytes), mode:stat.mode & 0o777, bytes }
}
const stateOf = ({bytes,...state}) => state
export async function snapshotFiles({workspace, files, binding, stateRoot=join(homedir(),'.local','state','sub2api-j-bridge')}) {
  validateRollbackFiles(files)
  workspace = await realpath(workspace)
  stateRoot = resolve(stateRoot)
  await mkdir(dirname(stateRoot),{recursive:true,mode:0o700})
  stateRoot = join(await realpath(dirname(stateRoot)), stateRoot.slice(stateRoot.lastIndexOf(sep) + 1))
  if (stateRoot === workspace || stateRoot.startsWith(workspace + sep)) throw Error('snapshot_directory_inside_workspace')
  await mkdir(stateRoot,{recursive:true,mode:0o700})
  stateRoot = await realpath(stateRoot)
  if (stateRoot === workspace || stateRoot.startsWith(workspace + sep)) throw Error('snapshot_directory_inside_workspace')
  if ((await lstat(stateRoot)).mode & 0o077) throw Error('snapshot_directory_not_private')
  const lock = join(stateRoot,'lock-'+hash(workspace))
  await mkdir(lock,{mode:0o700}).catch(error => { if (error.code==='EEXIST') throw Error('workspace_write_in_progress'); throw error })
  const directory = join(stateRoot,'snapshot-'+randomUUID())
  try {
    await mkdir(directory,{mode:0o700})
    const entries=[]; let total=0
    for (const file of files) {
      const before=await fingerprint(workspace,file); total+=before.bytes?.length || 0
      if (total>maxBytes) throw Error('snapshot_too_large')
      const backup=String(entries.length)+'.bin'
      if (before.bytes) await writeFile(join(directory,backup),before.bytes,{flag:'wx',mode:0o600})
      entries.push({file,backup,before:stateOf(before)})
    }
    const record={version:1,workspace,binding,created_at:new Date().toISOString(),outcome:'pending',entries}
    const persist=()=>writeFile(join(directory,'snapshot.json'),JSON.stringify(record,null,2),{mode:0o600})
    await persist()
    return {directory,async finish(outcome) {
      record.outcome=outcome
      try {
        for (const entry of entries) {
          try { entry.after=stateOf(await fingerprint(workspace,entry.file)) }
          catch { entry.after={unsafe:true}; record.outcome='manual_inspection_required' }
        }
        await persist()
      } finally { await rmdir(lock) }
    }}
  } catch(error) { await rmdir(lock); throw error }
}
export async function restoreSnapshot(directory) {
  directory=await realpath(resolve(directory))
  if ((await lstat(directory)).mode&0o077) throw Error('snapshot_directory_not_private')
  const record=JSON.parse(await readFile(join(directory,'snapshot.json'),'utf8'))
  if(record.version!==1 || !['completed','unknown'].includes(record.outcome) || !Array.isArray(record.entries)) throw Error('snapshot_not_restorable')
  validateRollbackFiles(record.entries.map(entry=>entry.file))
  const workspace=await realpath(record.workspace)
  if(workspace!==record.workspace) throw Error('snapshot_workspace_changed')
  const lock=join(dirname(directory),'lock-'+hash(workspace))
  await mkdir(lock,{mode:0o700}).catch(error=>{if(error.code==='EEXIST')throw Error('workspace_write_in_progress');throw error})
  try {
    const restores=[]
    for(const [i,entry] of record.entries.entries()) {
      if(entry.backup!==String(i)+'.bin') throw Error('snapshot_invalid_backup')
      const current=stateOf(await fingerprint(workspace,entry.file))
      if(JSON.stringify(current)!==JSON.stringify(entry.after)) throw Error('rollback_conflict')
      let bytes
      if(entry.before.exists) {
        const path=join(directory,entry.backup),stat=await lstat(path)
        if(!stat.isFile()||stat.nlink!==1||stat.size>maxBytes)throw Error('snapshot_invalid_backup')
        bytes=await readFile(path)
        if(hash(bytes)!==entry.before.sha256) throw Error('snapshot_backup_changed')
      }
      restores.push({entry,bytes})
    }
    for(const {entry,bytes} of restores) {
      const {path}=await target(workspace,entry.file)
      if(bytes) {
        const temporary=path+'.j-restore-'+randomUUID()
        await writeFile(temporary,bytes,{flag:'wx',mode:0o600})
        await chmod(temporary,entry.before.mode)
        await rename(temporary,path)
      } else if(entry.after.exists) await unlink(path)
    }
    record.outcome='restored';record.restored_at=new Date().toISOString()
    await writeFile(join(directory,'snapshot.json'),JSON.stringify(record,null,2),{mode:0o600})
    return {restored:restores.length}
  }finally{await rmdir(lock)}
}
