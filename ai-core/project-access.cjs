'use strict';

module.exports=async function projectAccess(pool,project,subject,email) {
 const found=await pool.query(`SELECT p.id FROM projects p JOIN users u ON u.id=$2 AND u.email=$3
     WHERE p.id=$1 AND (p.created_by=u.id OR EXISTS
       (SELECT 1 FROM project_members pm WHERE pm.project_id=p.id AND pm.user_email=u.email))`,
      [Number(project),subject,email]);
 return found.rows.length===1;
};
