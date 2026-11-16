'use strict';
// One HTTP stream for every size. Only the descriptor is buffered; data is
// processed in bounded blocks using the existing immutable chunk storage.
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
const crypto=require('node:crypto');
const BLOCK=262144,HEADER=1200000,TYPE='application/x-bimchat-delta-v1';
class Reader{
 constructor(source){this.iterator=source[Symbol.asyncIterator]();this.current=Buffer.alloc(0);this.at=0;}
 async read(count){const result=Buffer.alloc(count);let at=0;while(at<count){if(this.at===this.current.length){const part=await this.iterator.next();need(!part.done,'STREAM_DELTA_INCOMPLETE');this.current=Buffer.from(part.value);this.at=0;if(!this.current.length)continue;}const n=Math.min(count-at,this.current.length-this.at);this.current.copy(result,at,this.at,this.at+n);this.at+=n;at+=n;}return result;}
 async end(){need(this.at===this.current.length,'STREAM_DELTA_TRAILING');for(;;){const part=await this.iterator.next();if(part.done)return;need(!part.value.length,'STREAM_DELTA_TRAILING');}}
 async header(){const length=(await this.read(4)).readUInt32LE();need(length>0&&length<=HEADER,'STREAM_BODY');return JSON.parse((await this.read(length)).toString('utf8'));}
}
function prefix(body){const text=Buffer.from(JSON.stringify(body));need(text.length>0&&text.length<=HEADER,'STREAM_BODY');const size=Buffer.alloc(4);size.writeUInt32LE(text.length);return Buffer.concat([size,text]);}
module.exports=function({deltas,queue,pool,schema,validateModel,wake}){
 async function upload(auth,body,reader){
  need(Object.keys(body).sort().join(',')==='fileId,operation','STREAM_DELTA_FIELDS');validateModel(body.operation);
  const id=body.operation.patch.OperationId;
  await queue.reserve(auth,body.operation);await deltas.begin(auth,body.operation);
  // A replay uses exactly the same ID/descriptor/chunks. Existing storage rejects
  // altered bytes, and the queue cannot commit an operation twice.
  for(const f of body.operation.patch.Files){
   const hash=crypto.createHash('sha256');
   for(let at=0,index=0;at<f.DeltaLength;at+=BLOCK,index++){
    const bytes=await reader.read(Math.min(BLOCK,f.DeltaLength-at));hash.update(bytes);
    await deltas.put(auth,{operationId:id,name:f.Name,index,bytes:bytes.toString('base64')});
   }
   need(hash.digest('hex').toUpperCase()===f.DeltaHash,'STREAM_DELTA_HASH');
  }
  await reader.end();
  const old=await queue.status(auth,id);if(old.state==='accepted'||old.state==='rejected')return old;
  const verified=await deltas.verified(auth,id);await queue.enqueue(auth,verified,true);wake();
  return queue.status(auth,id); // queued is never reported as accepted.
 }
 async function* download(auth,body){
  need(Object.keys(body).sort().join(',')==='fileId,operationId','STREAM_DELTA_FIELDS');
  const c=await pool.connect();try{
   const op=(await c.query('SELECT payload FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1 AND operation_id=$2',[auth.fileId,body.operationId])).rows[0];
   need(op?.payload?.patch?.Schema===schema,'STREAM_DELTA_NOT_COMMITTED');validateModel(op.payload);
   yield prefix({operationId:body.operationId});
   for(const f of op.payload.patch.Files){const hash=crypto.createHash('sha256');
    for(let at=0,index=0;at<f.DeltaLength;at+=BLOCK,index++){
     const part=(await c.query('SELECT bytes FROM bimchat_direct_ownership.stream_image_chunks WHERE file_id=$1 AND operation_id=$2 AND file_name=$3 AND chunk_index=$4',[auth.fileId,body.operationId,f.Name,index])).rows[0];
     need(part&&part.bytes.length===Math.min(BLOCK,f.DeltaLength-at),'STREAM_DELTA_INCOMPLETE');hash.update(part.bytes);yield part.bytes;
    }need(hash.digest('hex').toUpperCase()===f.DeltaHash,'STREAM_DELTA_HASH');
   }
  }finally{c.release();}
 }
 return {upload,download};
};
Object.assign(module.exports,{Reader,prefix,TYPE,BLOCK,HEADER});
