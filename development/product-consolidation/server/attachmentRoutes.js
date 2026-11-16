'use strict';
const crypto=require('node:crypto');
const path=require('node:path');
const multer=require('multer');
const access=require('./chatAccess');
module.exports=function registerAttachments(app,pool,auth,storage) {
    // Buffer bounded multipart before authorization; no cloud upload happens until parent access succeeds.
    const receive=multer({storage:multer.memoryStorage(),fileFilter:(req,file,cb)=>cb(null,['.jpg','.jpeg','.png','.gif','.pdf','.dwg','.rvt'].includes(path.extname(file.originalname).toLowerCase())),limits:{fileSize:10*1024*1024,files:1,fields:3}}).single('file');
    const dto=(req,a)=>({
        id:a.id,user_email:a.user_email,file_name:a.file_name,file_type:a.file_type,file_size:a.file_size,resource_type:a.resource_type,
        file_url:req.protocol+'://'+req.get('host')+'/attachments/'+encodeURIComponent(a.id)+'/content',
        message_id:a.message_id,task_id:a.task_id,comment_id:a.comment_id,created_at:a.created_at
    });
    async function find(db,id,email) {
        const r=await db.query('SELECT * FROM attachments WHERE id=$1 FOR SHARE',[id]);
        if(!r.rows.length) access.reject(404,'Attachment not found');
        await access.parent(db,r.rows[0],email);
        return r.rows[0];
    }
    app.post('/attachments/upload',auth,(req,res,next)=>receive(req,res,err=>{
        if(err) return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'File too large. Maximum size is 10 MB.':'Invalid attachment upload'});
        next();
    }),access.route(pool,async(db,req)=>{
        await access.parent(db,req.body,req.user.email);
        if(!req.file) access.reject(400,'No file uploaded');
        const saved=await storage.save(req.file);
        try {
            const a=(await db.query(`INSERT INTO attachments
                (id,user_email,file_url,file_name,file_type,file_size,cloudinary_public_id,resource_type,storage_type,message_id,task_id,comment_id)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
                [crypto.randomUUID(),req.user.email,saved.url,req.file.originalname,req.file.mimetype,req.file.size,
                    saved.id,saved.resource,saved.type,req.body.message_id || null,req.body.task_id || null,req.body.comment_id || null])).rows[0];
            return {httpStatus:201,json:{success:true,attachment:dto(req,a)}};
        } catch(e) {
            await storage.remove({cloudinary_public_id:saved.id,resource_type:saved.resource,storage_type:saved.type}).catch(()=>{});
            throw e;
        }
    }));
    for(const [kind,column] of [['message','message_id'],['task','task_id'],['comment','comment_id']]) {
        app.get('/attachments/'+kind+'/:parentId',auth,access.route(pool,async(db,req)=>{
            await access.parent(db,{[column]:req.params.parentId},req.user.email);
            const rows=(await db.query('SELECT * FROM attachments WHERE '+column+'=$1 ORDER BY created_at',[req.params.parentId])).rows;
            // Fail closed on malformed historical rows with multiple parents.
            const result=[];
            for(const a of rows){await access.parent(db,a,req.user.email);result.push(dto(req,a));}
            return result;
        }));
    }
    app.get('/attachments/:id',auth,access.route(pool,async(db,req)=>dto(req,await find(db,req.params.id,req.user.email))));
    app.get('/attachments/:id/content',auth,access.route(pool,async(db,req)=>{
        const a=await find(db,req.params.id,req.user.email);
        return {bytes:await storage.read(a),name:a.file_name};
    }));
    app.delete('/attachments/:id',auth,access.route(pool,async(db,req)=>{
        const a=await find(db,req.params.id,req.user.email);
        if(a.user_email!==req.user.email) access.reject(403,'Not authorized to delete this attachment');
        await storage.remove(a);
        await db.query('DELETE FROM attachments WHERE id=$1',[a.id]);
        return {success:true,message:'Attachment deleted'};
    }));
};
