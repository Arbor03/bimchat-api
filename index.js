const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT,
                password_hash TEXT NOT NULL,
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
        const { email, full_name, password } = req.body;
        const fullName = full_name;
        const passwordHash = await bcrypt.hash(password, 10);

        const result = await pool.query(
            'INSERT INTO users (email, full_name, password_hash) VALUES ($1, $2, $3) RETURNING id, email, full_name',
            [email.toLowerCase(), fullName, passwordHash]
        );

        const token = jwt.sign(
            { id: result.rows[0].id, email: result.rows[0].email },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({ token, email: result.rows[0].email, fullName: result.rows[0].full_name });
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

        res.json({ token, email: user.email, fullName: user.full_name });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== TASK ROUTES ====================

app.get('/tasks/:projectName', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM tasks WHERE project_name = $1 ORDER BY created_at ASC',
            [req.params.projectName]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/tasks', authenticateToken, async (req, res) => {
    try {
        const { id, project_name, description, assignee, created_by, element_id, element_name, view_name, status } = req.body;

        await pool.query(
            `INSERT INTO tasks (id, project_name, description, assignee, created_by, element_id, element_name, view_name, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [id, project_name, description, assignee, created_by, element_id || -1, element_name || '', view_name || '', status || 'Open']
        );

        await pool.query(
            `INSERT INTO notifications (id, type, message, created_by, task_id, project_name)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [require('crypto').randomUUID(), 'NewTask', `${created_by} created new task: '${description}'`, created_by, id, project_name]
        );

        res.json({ success: true });
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
            [require('crypto').randomUUID(), 'NewComment', `${author} commented: '${text}'`, author, task_id, project_name]
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
        const result = await pool.query(
            `SELECT * FROM messages 
             WHERE project_name = $1 AND receiver IS NULL 
             ORDER BY created_at ASC LIMIT 100`,
            [req.params.projectName]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/messages/private/:projectName/:otherUser', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM messages 
             WHERE project_name = $1 AND (
                (sender = $2 AND receiver = $3) OR 
                (sender = $3 AND receiver = $2)
             )
             ORDER BY created_at ASC LIMIT 100`,
            [req.params.projectName, req.user.email, req.params.otherUser]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/messages', authenticateToken, async (req, res) => {
    try {
        const { id, project_name, message, receiver, element_id, element_name } = req.body;
        await pool.query(
            `INSERT INTO messages (id, project_name, sender, receiver, message, element_id, element_name)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [id, project_name, req.user.email, receiver || null, message, element_id || -1, element_name || null]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/users/:projectName', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT email, full_name FROM users ORDER BY full_name ASC`
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    await initDB();
    console.log(`BIM Chat API running on port ${PORT}`);
});