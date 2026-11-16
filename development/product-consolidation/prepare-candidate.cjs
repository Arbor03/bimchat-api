'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=__dirname, baseline=path.resolve(root,'../ownership-native-gate/review/slog-wire-fix-20261115/server-release');
let source=fs.readFileSync(path.join(baseline,'index.js'),'utf8');
const start=source.indexOf('// ==================== TASK ROUTES ===================='), end=source.indexOf('// ==================== START SERVER ====================');
if(start<0||end<start) throw Error('Unexpected baseline route boundaries');
source=source.slice(0,start)+`// ==================== COLLABORATION ROUTES ====================
require('./collaborationRoutes')(app,pool,authenticateToken,
    require('./attachmentStorage').createAttachmentStorage(false,cloudinary));

`+source.slice(end);
// Append migrations after all referenced tables exist, fixing the empty-database ordering.
const marker="        console.log('Database initialized successfully!');";
if(!source.includes(marker)) throw Error('Missing schema marker');
source=source.replace(marker,`        await pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE');
        await pool.query('ALTER TABLE tasks ADD COLUMN IF NOT EXISTS source_message_id TEXT');
        await pool.query("ALTER TABLE attachments ADD COLUMN IF NOT EXISTS storage_type TEXT DEFAULT 'upload'");
`+marker);
fs.writeFileSync(path.join(root,'server/index.js'),source);
const hashes={baseline:path.relative(root,baseline),files:{}};
for(const name of fs.readdirSync(baseline)) {
    const from=path.join(baseline,name), to=path.join(root,'server',name);
    if(!fs.statSync(from).isFile()) continue;
    const sha=f=>crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
    hashes.files[name]={baseline:sha(from),candidate:sha(to)};
}
fs.writeFileSync(path.join(root,'baseline-comparison.json'),JSON.stringify(hashes,null,2));
