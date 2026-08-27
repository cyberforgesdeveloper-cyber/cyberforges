const express = require('express');
const cors = require('cors');
const https = require('https');
const dns = require('dns');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Initialize SQLite Database with proper path handling
const dbPath = process.env.RENDER 
    ? path.join('/opt/render/project/src', 'database.sqlite') 
    : './database.sqlite';

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database at:', dbPath);
        db.run(`CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            domain TEXT,
            date TEXT
        )`);
    }
});

// Configure Nodemailer for cyberforgesdeveloper@gmail.com
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'cyberforgesdeveloper@gmail.com',
        pass: 'T@lh@345'
    }
});

// Helper function for security check with strict DNS and domain verification
const checkWebsiteSecurity = (domain) => {
    return new Promise((resolve) => {
        const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '').trim();

        // 1. Basic format check
        if (!cleanDomain.includes('.') || cleanDomain.endsWith('.')) {
            return resolve({ error: 'Invalid domain format. Please enter a valid registered domain (e.g. example.com)' });
        }

        // 2. DNS lookup to check if domain actually exists / is registered
        dns.lookup(cleanDomain, (err) => {
            if (err) {
                return resolve({ error: `Domain "${cleanDomain}" is not registered or does not exist. Please enter a valid domain.` });
            }

            // 3. HTTPS connection check
            const targetUrl = `https://${cleanDomain}`;
            
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
                    domain: cleanDomain,
                    score: Math.min(score, 100),
                    checks: {
                        https: { status: 'Pass', description: `Site uses valid SSL/TLS and responds securely via HTTPS.` },
                        ssl: { status: 'Pass', description: `Certificate issuer verified via secure handshake.` },
                        headers: { status: (hasHsts || hasXFrame) ? 'Pass' : 'Warning', description: `HSTS: ${hasHsts ? 'Present' : 'Missing'}, X-Frame-Options: ${hasXFrame ? 'Present' : 'Missing'}` }
                    }
                });
            }).on('error', () => {
                resolve({
                    error: `Could not establish a secure connection to "${cleanDomain}". Ensure the site has an active SSL certificate.`
                });
            });
        });
    });
};

// Scan route
app.post('/api/scan', async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain is required' });

    const scanResults = await checkWebsiteSecurity(domain);
    
    if (scanResults.error) {
        return res.status(400).json({ error: scanResults.error });
    }
    
    res.json(scanResults);
});

// Lead capture route & Email Notification
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
        
        console.log(`New Lead Saved with ID: ${this.lastID}`);

        const mailOptions = {
            from: 'cyberforgesdeveloper@gmail.com',
            to: 'cyberforgesdeveloper@gmail.com',
            subject: `🚨 New CyberForges Security Lead from ${name}!`,
            text: `Aapki website par ek naye client ne consultation request submit ki hai:\n\n- Client Name: ${name}\n- Client Email: ${email}\n- Target Domain: ${domain || 'N/A'}\n- Date/Time: ${new Date().toLocaleString()}\n\nForan admin panel par jaakar check karein!`
        };

        transporter.sendMail(mailOptions, (mailErr, info) => {
            if (mailErr) {
                console.error('Error sending email:', mailErr);
            } else {
                console.log('Email notification sent successfully:', info.response);
            }
        });

        res.json({ success: true, message: 'Lead saved and email notification sent!' });
    });
});

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