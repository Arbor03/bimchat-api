'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const {need} = require('./scoped-api-v11/scope.cjs');
const names = ['editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'];
const maxBytes = 8 * 1024 * 1024;
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();

async function accepted(c,file,epoch,sequence) {
 const {rows} = await c.query(
  'SELECT operation_id,result_pins FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1 AND sequence=$2 AND payload->>\'epoch\'=$3',
  [file,sequence,epoch]);
 return rows[0];
}

async function warm(c,cache,file,epoch,sequence,restore) {
 const previous=cache.current;
 if(previous?.file===file && previous.epoch===epoch && previous.sequence>=sequence)return 'superseded';
 const row=await accepted(c,file,epoch,sequence);
 if(!row)return 'unavailable';
 const pins=names.map(name=>row.result_pins.files.find(pin=>pin.name===name));
 need(pins.every(pin=>pin && Number.isSafeInteger(pin.length) && pin.length>=0 && /^[0-9A-F]{64}$/.test(pin.sha256)),'CHECKPOINT_PINS');
 if(pins.reduce((sum,pin)=>sum+pin.length,0)>maxBytes)return 'oversize';
 const prior=await lookup(c,cache,file,epoch,sequence);
 const files=new Map();
 for(const pin of pins){
  if(cache.current!==previous)return 'superseded';
  const filePath=await restore(pin.name,prior);
  need((await fs.stat(filePath)).size===pin.length,'CHECKPOINT_LENGTH');
  const bytes=await fs.readFile(filePath);
  need(hash(bytes)===pin.sha256,'CHECKPOINT_HASH');
  files.set(pin.name,bytes);
 }
 if(cache.current!==previous)return 'superseded';
 cache.current={file,epoch,sequence,id:row.operation_id,files};
 return 'ready';
}

async function lookup(c,cache,file,epoch,sequence) {
 const saved = cache.current;
 if(!saved || saved.file!==file || saved.epoch!==epoch || saved.sequence>sequence)return null;
 const row = await accepted(c,file,epoch,saved.sequence);
 if(!row || row.operation_id!==saved.id)return null;
 const pins = new Map(row.result_pins.files.map(pin=>[pin.name,pin]));
 return {saved,pins};
}

async function materialize(checkpoint,name,dir) {
 if(!checkpoint)return null;
 const {saved,pins} = checkpoint;
 const bytes = saved.files.get(name), pin = pins.get(name);
 if(!Buffer.isBuffer(bytes) || !pin || bytes.length!==pin.length || hash(bytes)!==pin.sha256)return null;
 const filePath = path.join(dir,name+'.checkpoint');
 await fs.writeFile(filePath,bytes,{flag:'wx'});
 return {filePath,sequence:saved.sequence};
}

function stage(file,patch) {
 const parts=patch.Files.filter(f=>names.includes(f.Name));
 if(parts.length!==names.length || parts.reduce((n,f)=>n+f.PostLength,0)>maxBytes)return null;
 return {file,epoch:patch.Generation,sequence:patch.Sequence,id:patch.OperationId,files:new Map()};
}
async function promote(c,cache,file,id,sequence) {
 const staged=cache.staged;
 if(!staged || staged.file!==file || staged.id!==id || staged.sequence!==sequence)return;
 if(cache.current?.epoch===staged.epoch && cache.current.sequence>=sequence)return;
 const row=await accepted(c,file,staged.epoch,sequence);
 if(row?.operation_id!==id)return;
 for(const name of names){
  const pin=row.result_pins.files.find(p=>p.name===name),bytes=staged.files.get(name);
  if(!pin || !bytes || bytes.length!==pin.length || hash(bytes)!==pin.sha256)return;
 }
 if(cache.staged===staged){
  cache.current=staged;
  cache.staged=null;
 }
}
module.exports={lookup,materialize,stage,promote,warm};
