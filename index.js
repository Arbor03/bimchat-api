const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();
const { Resend } = require('resend');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ==================== CLOUDINARY CONFIG ====================

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
});

if (!process.env.CLOUDINARY_CLOUD_NAME) {
    console.error('⚠️  CLOUDINARY credentials not configured!');
} else {
    console.log('✅ Cloudinary configured:', process.env.CLOUDINARY_CLOUD_NAME);
}

const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.dwg', '.rvt'];

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: (req, file) => {
        const ext = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
        const isImage = ['.jpg', '.jpeg', '.png', '.gif'].includes(ext);
        
        return {
            folder: 'bimchat',
            resource_type: isImage ? 'image' : 'raw',
            public_id: `${Date.now()}_${file.originalname.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9]/g, '_')}`,
            format: isImage ? undefined : ext.substring(1)
        };
    }
});

const fileFilter = (req, file, cb) => {
    const ext = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
        return cb(new Error(`File type not allowed. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`), false);
    }
    cb(null, true);
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10 MB
    }
});

// Email transporter for password reset
const resend = new Resend(process.env.RESEND_API_KEY);
if (process.env.RESEND_API_KEY) {
    console.log('✅ Resend email service configured');
} else {
    console.warn('⚠️  RESEND_API_KEY not configured - password reset emails disabled');
}
 
// Verify email config on startup

async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'BIM Specialist',
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        try { await pool.query(`ALTER TABLE revit_files ADD CONSTRAINT revit_files_guid_unique UNIQUE (revit_project_guid)`); } catch {}

        // Add role column if it doesn't exist (for existing databases)
        try { await pool.query(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'BIM Specialist'`); } catch {}

        await pool.query(`
            CREATE TABLE IF NOT EXISTS password_resets (
                id SERIAL PRIMARY KEY,
                email TEXT NOT NULL,
                token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS projects (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                created_by INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        // Add new columns to projects if they don't exist
        try { await pool.query(`ALTER TABLE projects ADD COLUMN description TEXT`); } catch {}
        try { await pool.query(`ALTER TABLE projects ADD COLUMN status TEXT DEFAULT 'Active'`); } catch {}
        try { await pool.query(`ALTER TABLE projects ADD COLUMN deadline TIMESTAMP`); } catch {}

        // Project members (user in project with role)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS project_members (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                user_email TEXT NOT NULL,
                role TEXT DEFAULT 'Specialist',
                added_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(project_id, user_email)
            )
        `);
        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_members_project ON project_members(project_id)`); } catch {}
        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_members_email ON project_members(user_email)`); } catch {}

        // Revit files linked to projects
        await pool.query(`
            CREATE TABLE IF NOT EXISTS revit_files (
                id SERIAL PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                file_name TEXT NOT NULL,
                file_path TEXT,
                revit_project_guid TEXT,
                linked_by TEXT,
                linked_at TIMESTAMP DEFAULT NOW()
            )
        `);
        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_revit_files_project ON revit_files(project_id)`); } catch {}
        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_revit_files_guid ON revit_files(revit_project_guid)`); } catch {}

        await pool.query(`
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                project_name TEXT NOT NULL,
                description TEXT NOT NULL,
                assignee TEXT,
                created_by TEXT,
                element_id INTEGER DEFAULT -1,
                element_name TEXT,
                view_name TEXT,
                status TEXT DEFAULT 'Open',
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS comments (
                id TEXT PRIMARY KEY,
                task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
                author TEXT,
                text TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                message TEXT NOT NULL,
                created_by TEXT,
                task_id TEXT,
                project_name TEXT,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                project_name TEXT NOT NULL,
                sender TEXT NOT NULL,
                receiver TEXT,
                message TEXT NOT NULL,
                element_id INTEGER DEFAULT -1,
                element_name TEXT,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        try { await pool.query(`ALTER TABLE messages ADD COLUMN element_id INTEGER DEFAULT -1`); } catch {}
        try { await pool.query(`ALTER TABLE messages ADD COLUMN element_name TEXT`); } catch {}
        // Add file_id for two-level communication
        try { await pool.query(`ALTER TABLE tasks ADD COLUMN file_id INTEGER REFERENCES revit_files(id) ON DELETE SET NULL`); } catch {}
        try { await pool.query(`ALTER TABLE messages ADD COLUMN file_id INTEGER REFERENCES revit_files(id) ON DELETE SET NULL`); } catch {}
        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_tasks_file ON tasks(file_id)`); } catch {}
        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_file ON messages(file_id)`); } catch {}

        await pool.query(`
            CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                file_url TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                cloudinary_public_id TEXT NOT NULL,
                resource_type TEXT DEFAULT 'image',
                message_id TEXT REFERENCES messages(id) ON DELETE CASCADE,
                task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
                comment_id TEXT REFERENCES comments(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id)`); } catch {}
        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_attachments_task ON attachments(task_id)`); } catch {}
        try { await pool.query(`CREATE INDEX IF NOT EXISTS idx_attachments_comment ON attachments(comment_id)`); } catch {}
        
        console.log('Database initialized successfully!');
    } catch (err) {
        console.error('Database init error:', err);
    }
}

function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// ==================== AUTH ROUTES ====================

app.post('/auth/register', async (req, res) => {
    try {
        const { email, full_name, password, role } = req.body;
        const fullName = full_name;
        const userRole = role || 'BIM Specialist';
        const passwordHash = await bcrypt.hash(password, 10);

        const result = await pool.query(
            'INSERT INTO users (email, full_name, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, role',
            [email.toLowerCase(), fullName, passwordHash, userRole]
        );

        const token = jwt.sign(
            { id: result.rows[0].id, email: result.rows[0].email },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({
            token,
            email: result.rows[0].email,
            fullName: result.rows[0].full_name,
            role: result.rows[0].role
        });
    } catch (err) {
        if (err.code === '23505') {
            res.status(400).json({ error: 'Email already exists' });
        } else {
            res.status(500).json({ error: err.message });
        }
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (result.rows.length === 0)
            return res.status(401).json({ error: 'Invalid email or password' });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword)
            return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({
            token,
            email: user.email,
            fullName: user.full_name,
            role: user.role || 'BIM Specialist'
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/**
 * GET /auth/verify
 * Verify if a token is valid and return user info
 */
app.get('/auth/verify', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, email, full_name, role FROM users WHERE email = $1',
            [req.user.email]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ error: 'User not found' });

        const user = result.rows[0];
        res.json({
            valid: true,
            email: user.email,
            fullName: user.full_name,
            role: user.role || 'BIM Specialist'
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/**
 * POST /auth/forgot-password
 * Generate a password reset token and send email
 */
app.post('/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const userResult = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email.toLowerCase()]
        );

        if (userResult.rows.length === 0) {
            // Security: don't reveal if email exists
            return res.json({ success: true, message: 'If the email exists, a reset code was sent' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const code = parseInt(token.substring(0, 6), 16).toString().substring(0, 6).padStart(6, '0');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        await pool.query(
            `INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, $3)`,
            [email.toLowerCase(), token, expiresAt]
        );

        if (process.env.RESEND_API_KEY) {
            try {
                await resend.emails.send({
                    from: 'BIM Chat <onboarding@resend.dev>',
                    to: email,
                    subject: 'BIM Chat - Password Reset Code',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;">
                            <h2 style="color: #2B579A;">Password Reset Request</h2>
                            <p>Your password reset code is:</p>
                            <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #2B579A; background: #f0f4ff; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                                ${code}
                            </div>
                            <p>This code expires in 1 hour.</p>
                            <p style="color: #888; font-size: 12px;">If you didn't request this, ignore this email.</p>
                        </div>
                    `
                });
                console.log(`✅ Reset code sent to ${email}`);
            } catch (emailErr) {
                console.error('Email send error:', emailErr);
                return res.status(500).json({ error: 'Failed to send email' });
            }
        } else {
            console.log(`⚠️ Reset code for ${email}: ${code} (email not configured)`);
        }

        res.json({ success: true, message: 'Reset code sent to your email' });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ error: err.message });
    }
});
app.post('/auth/reset-password', async (req, res) => {
    try {
        const { token, new_password } = req.body;
 
        if (!token || !new_password) {
            return res.status(400).json({ error: 'Code and new password are required' });
        }
 
        if (new_password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
 
        let resetRecord = null;
 
        // First try: match as full token
        let resetResult = await pool.query(
            `SELECT * FROM password_resets 
             WHERE token = $1 AND used = FALSE AND expires_at > NOW()
             ORDER BY created_at DESC LIMIT 1`,
            [token]
        );
 
        if (resetResult.rows.length > 0) {
            resetRecord = resetResult.rows[0];
        } else {
            // Second try: match as 6-digit code
            // Find all unused, non-expired tokens and check their codes
            const allTokens = await pool.query(
                `SELECT * FROM password_resets 
                 WHERE used = FALSE AND expires_at > NOW()
                 ORDER BY created_at DESC`
            );
 
            for (const row of allTokens.rows) {
                const code = parseInt(row.token.substring(0, 6), 16).toString().substring(0, 6).padStart(6, '0');
                if (code === token) {
                    resetRecord = row;
                    break;
                }
            }
        }
 
        if (!resetRecord) {
            return res.status(400).json({ error: 'Invalid or expired reset code' });
        }
 
        const email = resetRecord.email;
 
        const passwordHash = await bcrypt.hash(new_password, 10);
 
        await pool.query(
            'UPDATE users SET password_hash = $1 WHERE email = $2',
            [passwordHash, email]
        );
 
        await pool.query(
            'UPDATE password_resets SET used = TRUE WHERE id = $1',
            [resetRecord.id]
        );
 
        console.log(`✅ Password reset successful for ${email}`);
 
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// ==================== TASK ROUTES ====================
// ==================== PROJECT ROUTES ====================

// Get all projects for current user (projects where they are a member OR they created it)
app.get('/projects', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT p.*, 
                   u.email as creator_email,
                   u.full_name as creator_name,
                   pm.role as my_role,
                   (SELECT COUNT(*) FROM project_members WHERE project_id = p.id) as member_count,
                   (SELECT COUNT(*) FROM tasks WHERE project_name = p.name) as task_count
            FROM projects p
            LEFT JOIN users u ON p.created_by = u.id
            LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_email = $1
            WHERE pm.user_email = $1 OR u.email = $1
            ORDER BY p.created_at DESC
        `, [req.user.email]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get single project with members
app.get('/projects/:id', authenticateToken, async (req, res) => {
    try {
        const projectResult = await pool.query(
            `SELECT p.*, u.email as creator_email, u.full_name as creator_name
             FROM projects p
             LEFT JOIN users u ON p.created_by = u.id
             WHERE p.id = $1`,
            [req.params.id]
        );

        if (projectResult.rows.length === 0)
            return res.status(404).json({ error: 'Project not found' });

        const membersResult = await pool.query(
            `SELECT pm.*, u.full_name
             FROM project_members pm
             LEFT JOIN users u ON u.email = pm.user_email
             WHERE pm.project_id = $1
             ORDER BY pm.added_at ASC`,
            [req.params.id]
        );

        const filesResult = await pool.query(
            `SELECT * FROM revit_files WHERE project_id = $1 ORDER BY linked_at DESC`,
            [req.params.id]
        );

        res.json({
            ...projectResult.rows[0],
            members: membersResult.rows,
            files: filesResult.rows
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create new project
app.post('/projects', authenticateToken, async (req, res) => {
    try {
        const { name, description, deadline } = req.body;
        if (!name) return res.status(400).json({ error: 'Project name is required' });

        // Get user id
        const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [req.user.email]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        const userId = userResult.rows[0].id;

        // Create project
        const projectResult = await pool.query(
            `INSERT INTO projects (name, description, deadline, created_by)
             VALUES ($1, $2, $3, $4) RETURNING *`,
            [name, description || null, deadline || null, userId]
        );

        const project = projectResult.rows[0];

        // Auto-add creator as BIM Manager
        await pool.query(
            `INSERT INTO project_members (project_id, user_email, role)
             VALUES ($1, $2, $3)`,
            [project.id, req.user.email, 'BIM Manager']
        );

        res.json(project);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update project
app.put('/projects/:id', authenticateToken, async (req, res) => {
    try {
        const { name, description, deadline, status } = req.body;

        // Check permission: only BIM Manager can update
        const memberCheck = await pool.query(
            `SELECT role FROM project_members WHERE project_id = $1 AND user_email = $2`,
            [req.params.id, req.user.email]
        );
        if (memberCheck.rows.length === 0 || memberCheck.rows[0].role !== 'BIM Manager')
            return res.status(403).json({ error: 'Only BIM Manager can update project' });

        await pool.query(
            `UPDATE projects SET name = COALESCE($1, name), 
                description = COALESCE($2, description),
                deadline = COALESCE($3, deadline),
                status = COALESCE($4, status)
             WHERE id = $5`,
            [name, description, deadline, status, req.params.id]
        );

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete project
app.delete('/projects/:id', authenticateToken, async (req, res) => {
    try {
        // Check permission
        const memberCheck = await pool.query(
            `SELECT role FROM project_members WHERE project_id = $1 AND user_email = $2`,
            [req.params.id, req.user.email]
        );
        if (memberCheck.rows.length === 0 || memberCheck.rows[0].role !== 'BIM Manager')
            return res.status(403).json({ error: 'Only BIM Manager can delete project' });

        await pool.query('DELETE FROM projects WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== PROJECT MEMBERS ====================

// Add member to project
app.post('/projects/:id/members', authenticateToken, async (req, res) => {
    try {
        const { user_email, role } = req.body;
        if (!user_email) return res.status(400).json({ error: 'user_email is required' });

        // Check permission: only BIM Manager can add members
        const memberCheck = await pool.query(
            `SELECT role FROM project_members WHERE project_id = $1 AND user_email = $2`,
            [req.params.id, req.user.email]
        );
        if (memberCheck.rows.length === 0 || memberCheck.rows[0].role !== 'BIM Manager')
            return res.status(403).json({ error: 'Only BIM Manager can add members' });

        // Verify user exists
        const userCheck = await pool.query('SELECT id FROM users WHERE email = $1', [user_email.toLowerCase()]);
        if (userCheck.rows.length === 0) return res.status(404).json({ error: 'User not found' });

        await pool.query(
            `INSERT INTO project_members (project_id, user_email, role)
             VALUES ($1, $2, $3)
             ON CONFLICT (project_id, user_email) DO UPDATE SET role = $3`,
            [req.params.id, user_email.toLowerCase(), role || 'BIM Specialist']
        );

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Remove member from project
app.delete('/projects/:id/members/:email', authenticateToken, async (req, res) => {
    try {
        // Check permission
        const memberCheck = await pool.query(
            `SELECT role FROM project_members WHERE project_id = $1 AND user_email = $2`,
            [req.params.id, req.user.email]
        );
        if (memberCheck.rows.length === 0 || memberCheck.rows[0].role !== 'BIM Manager')
            return res.status(403).json({ error: 'Only BIM Manager can remove members' });

        await pool.query(
            `DELETE FROM project_members WHERE project_id = $1 AND user_email = $2`,
            [req.params.id, req.params.email.toLowerCase()]
        );

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update member role
app.put('/projects/:id/members/:email', authenticateToken, async (req, res) => {
    try {
        const { role } = req.body;

        // Check permission
        const memberCheck = await pool.query(
            `SELECT role FROM project_members WHERE project_id = $1 AND user_email = $2`,
            [req.params.id, req.user.email]
        );
        if (memberCheck.rows.length === 0 || memberCheck.rows[0].role !== 'BIM Manager')
            return res.status(403).json({ error: 'Only BIM Manager can change roles' });

        await pool.query(
            `UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_email = $3`,
            [role, req.params.id, req.params.email.toLowerCase()]
        );

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== REVIT FILES ====================

// Link a Revit file to a project
app.post('/projects/:id/link-file', authenticateToken, async (req, res) => {
    try {
        const { file_name, file_path, revit_project_guid } = req.body;
        if (!file_name) return res.status(400).json({ error: 'file_name is required' });

        const memberCheck = await pool.query(
            `SELECT role FROM project_members WHERE project_id = $1 AND user_email = $2`,
            [req.params.id, req.user.email]
        );
        if (memberCheck.rows.length === 0)
            return res.status(403).json({ error: 'You are not a member of this project' });

        const result = await pool.query(
            `INSERT INTO revit_files (project_id, file_name, file_path, revit_project_guid, linked_by)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (revit_project_guid) 
             DO UPDATE SET project_id = $1, file_path = $3, linked_by = $5
             RETURNING id`,
            [req.params.id, file_name, file_path || null, revit_project_guid || null, req.user.email]
        );

        res.json({ success: true, file_id: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Find project by Revit file GUID (used when opening a file in Revit)
app.get('/projects/by-file/:guid', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT p.*, rf.id as file_id, rf.file_name
             FROM revit_files rf
             JOIN projects p ON p.id = rf.project_id
             WHERE rf.revit_project_guid = $1
             LIMIT 1`,
            [req.params.guid]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ error: 'No project linked to this file' });

        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Unlink file from project
app.delete('/revit-files/:id', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM revit_files WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/tasks/:projectName', authenticateToken, async (req, res) => {
    try {
        const fileId = req.query.fileId; // undefined = all, 'project' = only project-level, number = specific file
        let query, params;

        if (fileId === 'project') {
            query = 'SELECT * FROM tasks WHERE project_name = $1 AND file_id IS NULL ORDER BY created_at ASC';
            params = [req.params.projectName];
        } else if (fileId) {
            query = 'SELECT * FROM tasks WHERE project_name = $1 AND file_id = $2 ORDER BY created_at ASC';
            params = [req.params.projectName, parseInt(fileId)];
        } else {
            query = 'SELECT * FROM tasks WHERE project_name = $1 ORDER BY created_at ASC';
            params = [req.params.projectName];
        }

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/tasks', authenticateToken, async (req, res) => {
    try {
        const { id, project_name, description, assignee, created_by, element_id, element_name, view_name, status, file_id } = req.body;

        await pool.query(
            `INSERT INTO tasks (id, project_name, description, assignee, created_by, element_id, element_name, view_name, status, file_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
            [id, project_name, description, assignee, created_by, element_id || -1, element_name || '', view_name || '', status || 'Open', file_id || null]
        );

        await pool.query(
            `INSERT INTO notifications (id, type, message, created_by, task_id, project_name)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [crypto.randomUUID(), 'NewTask', `${created_by} created new task: '${description}'`, created_by, id, project_name]
        );

        res.json({ success: true, id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/tasks/:id', authenticateToken, async (req, res) => {
    try {
        const { status, viewName, assignee } = req.body;

        await pool.query(
            'UPDATE tasks SET status = $1, view_name = $2, assignee = $3 WHERE id = $4',
            [status, viewName, assignee, req.params.id]
        );

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/tasks/:id', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM tasks WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== COMMENT ROUTES ====================

app.get('/comments/:taskId', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM comments WHERE task_id = $1 ORDER BY created_at ASC',
            [req.params.taskId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/comments', authenticateToken, async (req, res) => {
    try {
        const { id, task_id, author, text, project_name } = req.body;

        await pool.query(
            'INSERT INTO comments (id, task_id, author, text) VALUES ($1, $2, $3, $4)',
            [id, task_id, author, text]
        );

        await pool.query(
            `INSERT INTO notifications (id, type, message, created_by, task_id, project_name)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [crypto.randomUUID(), 'NewComment', `${author} commented: '${text}'`, author, task_id, project_name]
        );

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== NOTIFICATION ROUTES ====================

app.get('/notifications/:projectName', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM notifications 
             WHERE project_name = $1 AND created_by != $2 AND is_read = FALSE
             ORDER BY created_at DESC`,
            [req.params.projectName, req.user.email]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/notifications/read/:projectName', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'UPDATE notifications SET is_read = TRUE WHERE project_name = $1 AND created_by != $2',
            [req.params.projectName, req.user.email]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== MESSAGE ROUTES ====================

app.get('/messages/group/:projectName', authenticateToken, async (req, res) => {
    try {
        const fileId = req.query.fileId;
        let query, params;

        if (fileId === 'project') {
            query = `SELECT * FROM messages 
                     WHERE project_name = $1 AND receiver IS NULL AND file_id IS NULL
                     ORDER BY created_at ASC LIMIT 100`;
            params = [req.params.projectName];
        } else if (fileId) {
            query = `SELECT * FROM messages 
                     WHERE project_name = $1 AND receiver IS NULL AND file_id = $2
                     ORDER BY created_at ASC LIMIT 100`;
            params = [req.params.projectName, parseInt(fileId)];
        } else {
            query = `SELECT * FROM messages 
                     WHERE project_name = $1 AND receiver IS NULL 
                     ORDER BY created_at ASC LIMIT 100`;
            params = [req.params.projectName];
        }

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/messages/private/:projectName/:otherUser', authenticateToken, async (req, res) => {
    try {
        const fileId = req.query.fileId;
        let fileFilter = '';
        let params = [req.params.projectName, req.user.email, req.params.otherUser];

        if (fileId === 'project') {
            fileFilter = 'AND file_id IS NULL';
        } else if (fileId) {
            fileFilter = 'AND file_id = $4';
            params.push(parseInt(fileId));
        }

        const query = `SELECT * FROM messages 
             WHERE project_name = $1 AND (
                (sender = $2 AND receiver = $3) OR 
                (sender = $3 AND receiver = $2)
             ) ${fileFilter}
             ORDER BY created_at ASC LIMIT 100`;

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/messages', authenticateToken, async (req, res) => {
    try {
        const { id, project_name, message, receiver, element_id, element_name, file_id } = req.body;
        await pool.query(
            `INSERT INTO messages (id, project_name, sender, receiver, message, element_id, element_name, file_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [id, project_name, req.user.email, receiver || null, message, element_id || -1, element_name || null, file_id || null]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/users/:projectName', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT email, full_name, role FROM users ORDER BY full_name ASC`
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== ATTACHMENT ROUTES ====================

app.post('/attachments/upload', authenticateToken, (req, res) => {
    upload.single('file')(req, res, async (err) => {
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File too large. Maximum size is 10 MB.' });
            }
            return res.status(400).json({ error: err.message });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        try {
            const { message_id, task_id, comment_id } = req.body;
            const userEmail = req.user.email;

            const parentCount = [message_id, task_id, comment_id].filter(Boolean).length;
            if (parentCount > 1) {
                const resourceType = req.file.mimetype.startsWith('image/') ? 'image' : 'raw';
                await cloudinary.uploader.destroy(req.file.filename, { resource_type: resourceType });
                return res.status(400).json({ error: 'Attachment can belong to only one entity' });
            }

            const attachmentId = crypto.randomUUID();
            const ext = req.file.originalname.toLowerCase().substring(req.file.originalname.lastIndexOf('.'));
            const isImage = ['.jpg', '.jpeg', '.png', '.gif'].includes(ext);
            const resourceType = isImage ? 'image' : 'raw';
            const fileUrl = req.file.path;

            const result = await pool.query(
                `INSERT INTO attachments 
                    (id, user_email, file_url, file_name, file_type, file_size, 
                     cloudinary_public_id, resource_type, message_id, task_id, comment_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 RETURNING *`,
                [
                    attachmentId,
                    userEmail,
                    fileUrl,
                    req.file.originalname,
                    req.file.mimetype,
                    req.file.size,
                    req.file.filename,
                    resourceType,
                    message_id || null,
                    task_id || null,
                    comment_id || null
                ]
            );

            console.log(`✅ Attachment uploaded: ${req.file.originalname} by ${userEmail}`);

            res.status(201).json({
                success: true,
                attachment: result.rows[0]
            });

        } catch (error) {
            console.error('Upload error:', error);
            
            if (req.file && req.file.filename) {
                try {
                    const resourceType = req.file.mimetype.startsWith('image/') ? 'image' : 'raw';
                    await cloudinary.uploader.destroy(req.file.filename, { resource_type: resourceType });
                } catch (cleanupErr) {
                    console.error('Cleanup error:', cleanupErr);
                }
            }
            
            res.status(500).json({ error: error.message });
        }
    });
});

app.get('/attachments/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM attachments WHERE id = $1',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Attachment not found' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/attachments/message/:messageId', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM attachments WHERE message_id = $1 ORDER BY created_at ASC',
            [req.params.messageId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/attachments/task/:taskId', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM attachments WHERE task_id = $1 ORDER BY created_at ASC',
            [req.params.taskId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/attachments/comment/:commentId', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM attachments WHERE comment_id = $1 ORDER BY created_at ASC',
            [req.params.commentId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/attachments/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM attachments WHERE id = $1',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Attachment not found' });
        }

        const attachment = result.rows[0];

        if (attachment.user_email !== req.user.email) {
            return res.status(403).json({ error: 'Not authorized to delete this attachment' });
        }

        try {
            await cloudinary.uploader.destroy(attachment.cloudinary_public_id, {
                resource_type: attachment.resource_type || 'image'
            });
        } catch (cloudErr) {
            console.error('Cloudinary delete error:', cloudErr);
        }

        await pool.query('DELETE FROM attachments WHERE id = $1', [req.params.id]);

        console.log(`🗑️  Attachment deleted: ${attachment.file_name} by ${req.user.email}`);

        res.json({ success: true, message: 'Attachment deleted' });

    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    await initDB();
    console.log(`BIM Chat API running on port ${PORT}`);
});