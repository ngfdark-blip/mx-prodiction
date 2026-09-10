const express = require('express');
const app = express();
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// دامەزراندنا بنکەیا داتایێ SQLite3
const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )`);
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// تۆمارکرنا هەژمارێ (Signup)
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'ناڤ و پەیڤا نهێنی پێدڤی نە' });
        }
        if (username.length < 6) {
            return res.status(400).json({ error: 'ناڤێ بکارهێنەری نابێت ژ 6 پیتان کێمتر بێت' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'پەیڤا نهێنی نابێت ژ 8 پیتان کێمتر بێت' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) {
                return res.status(400).json({ error: 'ئەڤ ناڤە هەی یان هەڵەیەک هەیە' });
            }
            res.json({ message: 'ب سەرکەفتی هاتە تۆمارکرن', username });
        });
    } catch (err) {
        res.status(500).json({ error: 'خەلەتیەکا سێرڤەری ڕووی دا' });
    }
});

// چوونەژوورەوە (Login)
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'کۆم و پەیڤا نهێنی پڕ بکە' });
        }

        db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
            if (err || !user) {
                return res.status(400).json({ error: 'ناڤ یان پەیڤا نهێنی خەلەتە' });
            }

            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(400).json({ error: 'ناڤ یان پەیڤا نهێنی خەلەتە' });
            }

            res.json({ message: 'ب سەرکەفتی چوویە ژوور', username: user.username });
        });
    } catch (err) {
        res.status(500).json({ error: 'خەلەتیەکا سێرڤەری ڕووی دا' });
    }
});

// گۆڕینا ناڤێ بکارهێنەری
app.post('/api/update-username', async (req, res) => {
    const { oldUsername, newUsername } = req.body;
    if (!newUsername || newUsername.length < 6) {
        return res.status(400).json({ error: 'ناڤێ نوی نابێت ژ 6 پیتان کێمتر بێت' });
    }

    db.run(`UPDATE users SET username = ? WHERE username = ?`, [newUsername, oldUsername], function(err) {
        if (err) {
            return res.status(400).json({ error: 'ئەڤ ناڤە یێ هەی' });
        }
        res.json({ username: newUsername });
    });
});

// گۆڕینا پەیڤا نهێنی
app.post('/api/update-password', async (req, res) => {
    const { username, newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({ error: 'پەیڤا نهێنی یا نوی نابێت ژ 8 پیتان کێمتر بێت' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run(`UPDATE users SET password = ? WHERE username = ?`, [hashedPassword, username], function(err) {
        if (err) {
            return res.status(400).json({ error: 'خەلەتی ڕووی دا' });
        }
        res.json({ message: 'ب سەرکەفتی هاتە نووکرن' });
    });
});

// ژناڤبرنا هەژمارێ
app.post('/api/delete-account', (req, res) => {
    const { username } = req.body;
    db.run(`DELETE FROM users WHERE username = ?`, [username], function(err) {
        if (err) {
            return res.status(400).json({ error: 'نەهاتە ژناڤبرن' });
        }
        res.json({ message: 'هەژمار هاتە ژناڤبرن' });
    });
});

app.listen(PORT, () => {
    console.log(`MX Production Server is running on port ${PORT}`);
});
