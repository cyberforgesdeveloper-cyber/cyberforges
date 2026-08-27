const express = require('express');
const cors = require('cors');
const https = require('https');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Initialize SQLite Database
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create leads table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            domain TEXT,
            date TEXT
        )`);
    }
});

// Helper function for security check
const checkWebsiteSecurity = (domain) => {
    return new Promise((resolve) => {
        const targetUrl = `https://${domain}`;
        
        https.get(targetUrl, (res) => {
            const headers = res.headers;
            const hasHsts = !!headers['strict-transport-security'];
            const hasXFrame = !!headers['x-frame-options'];
            const hasCsp = !!headers['content-security-policy'];
            
            let score = 60;
            if (hasHsts) score += 15;
            if (hasXFrame) score += 15;
            if (hasCsp) score += 10;

            resolve({
                domain: domain,
                score: Math.min(score, 100),
                checks: {
                    https: { status: 'Pass', description: `Site uses valid SSL/TLS and responds securely via HTTPS.` },
                    ssl: { status: 'Pass', description: `Certificate issuer verified via secure handshake.` },
                    headers: { status: (hasHsts || hasXFrame) ? 'Pass' : 'Warning', description: `HSTS: ${hasHsts ? 'Present' : 'Missing'}, X-Frame-Options: ${hasXFrame ? 'Present' : 'Missing'}` }
                }
            });
        }).on('error', () => {
            resolve({
                domain: domain,
                score: 30,
                checks: {
                    https: { status: 'Fail', description: 'Could not establish a secure HTTPS connection.' },
                    ssl: { status: 'Fail', description: 'SSL Certificate check failed or domain unreachable.' },
                    headers: { status: 'Fail', description: 'Security headers could not be retrieved.' }
                }
            });
        });
    });
};

// Scan route
app.post('/api/scan', async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain is required' });

    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const scanResults = await checkWebsiteSecurity(cleanDomain);
    res.json(scanResults);
});

// Lead capture route (Saved to SQLite database)
app.post('/api/lead', (req, res) => {
    const { name, email, domain } = req.body;
    if (!name || !email) {
        return res.status(400).json({ error: 'Name and email are required' });
    }

    const date = new Date().toISOString();
    const query = `INSERT INTO leads (name, email, domain, date) VALUES (?, ?, ?, ?)`;

    db.run(query, [name, email, domain || 'N/A', date], function(err) {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ error: 'Failed to save lead in database' });
        }
        console.log(`New Lead Saved to Database with ID: ${this.lastID}`);
        res.json({ success: true, message: 'Lead saved successfully!' });
    });
});

// Get all captured leads from SQLite (Admin Route)
app.get('/api/leads', (req, res) => {
    const query = `SELECT * FROM leads ORDER BY id DESC`;
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ error: 'Failed to fetch leads' });
        }
        res.json(rows);
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});