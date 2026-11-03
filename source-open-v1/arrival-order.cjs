'use strict';
// Admission order within one API process. PostgreSQL still enforces exclusive
// model state. This is not a durable queue or a multi-replica FIFO guarantee.
const tails=new Map();
module.exports=async function ordered(key,work){
 const prior=tails.get(key)||Promise.resolve();let release;
 const current=new Promise(resolve=>{release=resolve;});tails.set(key,current);
 await prior;
 try{return await work();}finally{release();if(tails.get(key)===current)tails.delete(key);}
};
