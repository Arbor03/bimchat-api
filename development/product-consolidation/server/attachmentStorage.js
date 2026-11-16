'use strict';
const crypto=require('node:crypto');
function createAttachmentStorage(local,cloudinary) {
    if(local) {
        const files=new Map();
        return {
            async save(file) { const id=crypto.randomUUID(); files.set(id,Buffer.from(file.buffer)); return {id,url:'local-test-private',resource:file.mimetype.startsWith('image/')?'image':'raw',type:'authenticated'}; },
            async read(a) { const data=files.get(a.cloudinary_public_id); if(!data) throw new Error('Test attachment missing'); return data; },
            async remove(a) { files.delete(a.cloudinary_public_id); }
        };
    }
    return {
        async save(file) {
            const resource=file.mimetype.startsWith('image/')?'image':'raw';
            const result=await new Promise((resolve,reject)=>{
                const stream=cloudinary.uploader.upload_stream({
                    resource_type:resource,type:'authenticated',folder:'bimchat-private',
                    public_id:crypto.randomUUID(),timeout:20000
                },(err,value)=>err?reject(err):resolve(value));
                stream.end(file.buffer);
            });
            return {id:result.public_id,url:result.secure_url,resource,type:'authenticated'};
        },
        async read(a) {
            // Generate delivery only from our stored Cloudinary identity, never an arbitrary URL.
            const url=cloudinary.url(a.cloudinary_public_id,{secure:true,sign_url:true,
                resource_type:a.resource_type || 'image',type:a.storage_type || 'upload'});
            const response=await fetch(url,{signal:AbortSignal.timeout(20000)});
            if(!response.ok) throw new Error('Attachment storage unavailable');
            return Buffer.from(await response.arrayBuffer());
        },
        async remove(a) {
            await cloudinary.uploader.destroy(a.cloudinary_public_id,{
                resource_type:a.resource_type || 'image',type:a.storage_type || 'upload',invalidate:true});
        }
    };
}
module.exports={createAttachmentStorage};
