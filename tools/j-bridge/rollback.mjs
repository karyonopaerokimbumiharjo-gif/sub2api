// Explicit operator action. No automatic rollback of uncertain external effects.
import { restoreSnapshot } from './snapshot.mjs'
if(process.argv.length!==3)throw Error('usage: node rollback.mjs /absolute/snapshot-directory')
console.log(JSON.stringify(await restoreSnapshot(process.argv[2])))
