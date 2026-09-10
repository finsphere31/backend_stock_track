const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'stocktrack-jwt-super-secret-key-2026';

// Middleware
app.use(cors());
app.use(express.json());

// -------------------------------------------------------------
// Storage Directory & Master Database Initialization
// -------------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const masterDb = new Database(path.join(DATA_DIR, 'master.db'));
masterDb.pragma('journal_mode = WAL');

// Master schema: stores user metadata and credentials
masterDb.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        pin_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

// -------------------------------------------------------------
// Dynamic Tenant SQLite DB Manager
// -------------------------------------------------------------
const userDbCache = new Map();

function getUserDb(userId) {
    if (userDbCache.has(userId)) {
        return userDbCache.get(userId);
    }

    const dbPath = path.join(DATA_DIR, `user_${userId}.db`);
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');

    // Create personal user tables if not present
    db.exec(`
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL COLLATE NOCASE,
            supplier TEXT DEFAULT '',
            qty INTEGER DEFAULT 0,
            reminder TEXT DEFAULT '',
            threshold INTEGER DEFAULT 2
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            product TEXT NOT NULL,
            type TEXT CHECK(type IN ('purchase', 'sales')) NOT NULL,
            qty INTEGER NOT NULL,
            desc TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    `);

    userDbCache.set(userId, db);
    return db;
}

// -------------------------------------------------------------
// Auth Middleware: Injects user's private DB into req.userDb
// -------------------------------------------------------------
function authenticateUser(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        req.userDb = getUserDb(decoded.id);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Session expired or invalid token' });
    }
}

// -------------------------------------------------------------
// 1. Authentication Endpoints (Master DB)
// -------------------------------------------------------------

// POST /api/auth/register


app.get('/' , (req, res) => {
    res.send('StockTrack Multi-Tenant Backend is running.');
});
app.post('/api/auth/register', async (req, res) => {
    const { username, password, pin } = req.body;

    if (!username || !password || !pin) {
        return res.status(400).json({ error: 'All credentials (username, password, PIN) are required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (!/^\d{4}$/.test(pin)) {
        return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const pinHash = await bcrypt.hash(pin, 10);

        const stmt = masterDb.prepare(`
            INSERT INTO users (username, password_hash, pin_hash)
            VALUES (?, ?, ?)
        `);
        const info = stmt.run(username.trim().toLowerCase(), passwordHash, pinHash);

        const userId = info.lastInsertRowid;
        // Instantiate the user's isolated database file immediately
        getUserDb(userId);

        const token = jwt.sign({ id: userId, username: username.trim().toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });

        return res.status(201).json({
            message: 'User registered successfully',
            token,
            user: { id: userId, username: username.trim().toLowerCase() }
        });
    } catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(409).json({ error: 'That username is already taken' });
        }
        return res.status(500).json({ error: 'Internal database error' });
    }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Please enter username and password' });
    }

    const cleanUsername = username.trim().toLowerCase();
    const user = masterDb.prepare('SELECT * FROM users WHERE username = ?').get(cleanUsername);

    if (!user) {
        return res.status(401).json({ error: 'Incorrect username or password' });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
        return res.status(401).json({ error: 'Incorrect username or password' });
    }

    // Ensure the tenant's private SQLite file is created/opened
    getUserDb(user.id);

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });

    return res.json({
        message: 'Login successful',
        token,
        user: { id: user.id, username: user.username }
    });
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
    const { username, pin, newPassword } = req.body;

    if (!username || !pin || !newPassword) {
        return res.status(400).json({ error: 'Username, 4-digit PIN, and new password are required' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const cleanUsername = username.trim().toLowerCase();
    const user = masterDb.prepare('SELECT * FROM users WHERE username = ?').get(cleanUsername);

    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    const pinMatches = await bcrypt.compare(pin, user.pin_hash);
    if (!pinMatches) {
        return res.status(403).json({ error: 'Invalid 4-digit PIN' });
    }

    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    masterDb.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newPasswordHash, user.id);

    return res.json({ message: 'Password reset successful. You can now log in.' });
});

// -------------------------------------------------------------
// 2. Tenant Data Endpoints (Operates on the User's Personal DB)
// -------------------------------------------------------------

// GET /api/data/sync - Load entire database state for the user
app.get('/api/data/sync', authenticateUser, (req, res) => {
    const db = req.userDb;

    const products = db.prepare('SELECT * FROM products ORDER BY id DESC').all();
    const transactions = db.prepare('SELECT * FROM transactions ORDER BY id DESC').all();
    const settingsRows = db.prepare('SELECT key, value FROM app_settings').all();

    const settings = {};
    settingsRows.forEach(r => { settings[r.key] = r.value; });

    res.json({
        products,
        transactions,
        org_name: settings.org_name || '',
        report_header: settings.report_header || ''
    });
});

// POST /api/data/sync - Safe bulk sync
app.post('/api/data/sync', authenticateUser, (req, res) => {
    const db = req.userDb;
    const { products, transactions, org_name, report_header } = req.body;

    const syncTx = db.transaction(() => {
        // Only replace products if an array was explicitly provided
        if (Array.isArray(products)) {
            db.exec('DELETE FROM products');
            const insertProd = db.prepare(`
                INSERT INTO products (name, supplier, qty, reminder, threshold)
                VALUES (@name, @supplier, @qty, @reminder, @threshold)
            `);
            for (const p of products) {
                insertProd.run({
                    name: p.name,
                    supplier: p.supplier || '',
                    qty: parseInt(p.qty, 10) || 0,
                    reminder: p.reminder || '',
                    threshold: parseInt(p.threshold, 10) || 2
                });
            }
        }

        // Only replace transactions if an array was explicitly provided
        if (Array.isArray(transactions)) {
            db.exec('DELETE FROM transactions');
            const insertTx = db.prepare(`
                INSERT INTO transactions (date, product, type, qty, desc)
                VALUES (@date, @product, @type, @qty, @desc)
            `);
            for (const t of transactions) {
                insertTx.run({
                    date: t.date,
                    product: t.product,
                    type: t.type,
                    qty: parseInt(t.qty, 10) || 0,
                    desc: t.desc || ''
                });
            }
        }

        const upsertSetting = db.prepare(`
            INSERT INTO app_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `);
        if (org_name !== undefined) upsertSetting.run('org_name', String(org_name));
        if (report_header !== undefined) upsertSetting.run('report_header', String(report_header));
    });

    try {
        syncTx();
        res.json({ message: 'User database synchronized successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to sync user database: ' + err.message });
    }
});

// -------------------------------------------------------------
// Start Server
// -------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`StockTrack multi-tenant backend listening on http://localhost:${PORT}`);
    console.log(`Master DB: ${path.join(DATA_DIR, 'master.db')}`);
});
