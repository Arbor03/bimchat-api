'use strict';
// Add to each SDK client. This is application enforcement, not bucket IAM.
function check(command,args){const i=args.input||{};const keys=[i.Key,...((i.Delete&&i.Delete.Objects)||[]).map(o=>o.Key)];const sealed=keys.some(k=>typeof k==='string'&&k.startsWith('direct-sealed/'));if(!sealed)return;
 if(command==='GetObjectCommand'||command==='HeadObjectCommand'){if(!i.IfMatch)throw Error('SEALED_CONDITIONAL_READ_REQUIRED');return;}
 if(command==='PutObjectCommand'&&i.IfNoneMatch==='*')return;
 throw Error('SEALED_MUTATION_REFUSED');
}
function install(client){client.middlewareStack.add((next,context)=>async args=>{check(context.commandName,args);return next(args);},{step:'initialize',name:'sealedNamespaceGuard',priority:'high'});return client;}
module.exports={check,install};
