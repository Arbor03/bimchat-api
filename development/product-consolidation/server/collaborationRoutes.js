'use strict';
// Single mount point: no shadowed legacy routes remain in index.js.
module.exports=function registerCollaboration(app,pool,auth,storage) {
    require('./taskRoutes')(app,pool,auth);
    require('./chatRoutes')(app,pool,auth);
    require('./attachmentRoutes')(app,pool,auth,storage);
};
