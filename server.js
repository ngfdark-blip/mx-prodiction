const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Setup SQLite Database
const dbPath = path.resolve(__dirname, 'mx_production.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Database error:', err.message);
    else console.log('Connected to SQLite Database.');
});

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);

// Setup Multer for Uploads
const uploadDir = path.resolve(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage, limits: { fileSize: 500 * 1024 * 1024 } });

// API Routes
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || username.length < 6) return res.status(400).json({ error: 'ناڤێ بکارهێنەری دڤێت کێم نەبت ژ 6 پیتان!' });
    if (!password || password.length < 8) return res.status(400).json({ error: 'پەیڤا نهێنی دڤێت کێم نەبت ژ 8 پیتان!' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: 'ئەڤ ناڤە هاتیە گرتن!' });
            res.json({ success: true, username });
        });
    } catch (e) {
        res.status(500).json({ error: 'خەلەتیا سێرڤەری.' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'ناڤ یان پەیڤا نهێنی هەڵەیە!' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'ناڤ یان پەیڤا نهێنی هەڵەیە!' });
        res.json({ success: true, username: user.username });
    });
});

app.post('/api/update-username', (req, res) => {
    const { oldUsername, newUsername } = req.body;
    if (!newUsername || newUsername.length < 6) return res.status(400).json({ error: 'ناڤێ نوی کێمترە ژ 6 پیتان!' });
    db.run(`UPDATE users SET username = ? WHERE username = ?`, [newUsername, oldUsername], function(err) {
        if (err) return res.status(400).json({ error: 'ئەڤ ناڤە یێ هەی.' });
        res.json({ success: true, username: newUsername });
    });
});

app.post('/api/update-password', async (req, res) => {
    const { username, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'پەیڤا نهێنی کێمترە ژ 8 پیتان!' });
    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run(`UPDATE users SET password = ? WHERE username = ?`, [hashedPassword, username], (err) => {
            if (err) return res.status(400).json({ error: 'خەلەتی ڕوویدا.' });
            res.json({ success: true });
        });
    } catch (e) {
        res.status(500).json({ error: 'خەلەتیا سێرڤەری.' });
    }
});

app.post('/api/delete-account', (req, res) => {
    const { username } = req.body;
    db.run(`DELETE FROM users WHERE username = ?`, [username], (err) => {
        if (err) return res.status(400).json({ error: 'ژناڤبرن سەرکەفتی نەبوو.' });
        res.json({ success: true });
    });
});

app.post('/api/upload', upload.single('media'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'چ فایل نەهاتە بارکرن!' });
    res.json({ success: true, fileUrl: `/uploads/${req.file.filename}` });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
