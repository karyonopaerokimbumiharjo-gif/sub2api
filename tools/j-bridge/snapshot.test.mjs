import test from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink,link,access} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {snapshotFiles,restoreSnapshot,validateRollbackFiles} from './snapshot.mjs'
const fixture=async()=>{const root=await mkdtemp(join(tmpdir(),'j-snapshot-'));const workspace=join(root,'workspace');await mkdir(workspace);return {root,workspace,stateRoot:join(root,'private-snapshots')}}
test('R2 preserves old files and absent files; explicit rollback is repeat-safe',async()=>{
 const f=await fixture()
 try{
  await writeFile(join(f.workspace,'note'),'original',{mode:0o640})
  const s=await snapshotFiles({...f,files:['note','new'],binding:{task:'one',call:'one'}})
  await assert.rejects(snapshotFiles({...f,files:['note']}),/workspace_write_in_progress/)
  await writeFile(join(f.workspace,'note'),'changed');await writeFile(join(f.workspace,'new'),'created')
  await s.finish('completed')
  assert.deepEqual(await restoreSnapshot(s.directory),{restored:2})
  assert.equal(await readFile(join(f.workspace,'note'),'utf8'),'original')
  await assert.rejects(access(join(f.workspace,'new')),/ENOENT/)
  await assert.rejects(restoreSnapshot(s.directory),/snapshot_not_restorable/)
 }finally{await rm(f.root,{recursive:true,force:true})}
})
test('rollback cannot overwrite subsequent operator changes or follow a symlink',async()=>{
 const f=await fixture()
 try{
  await writeFile(join(f.workspace,'note'),'original')
  const s=await snapshotFiles({...f,files:['note']})
  await writeFile(join(f.workspace,'note'),'tool');await s.finish('unknown')
  await writeFile(join(f.workspace,'note'),'operator')
  await assert.rejects(restoreSnapshot(s.directory),/rollback_conflict/)
  assert.equal(await readFile(join(f.workspace,'note'),'utf8'),'operator')
  await symlink(f.root,join(f.workspace,'escape'))
  await assert.rejects(snapshotFiles({...f,files:['escape/private']}),/snapshot_symlink_rejected/)
  await link(join(f.workspace,'note'),join(f.workspace,'alias'))
  await assert.rejects(snapshotFiles({...f,files:['alias']}),/snapshot_unsafe_file/)
  assert.throws(()=>validateRollbackFiles(['../outside']),/rollback_files_required/)
  await assert.rejects(snapshotFiles({...f,files:['note'],stateRoot:join(f.workspace,'snapshots')}),/snapshot_directory_inside_workspace/)
 }finally{await rm(f.root,{recursive:true,force:true})}
})
