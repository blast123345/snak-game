require('dotenv').config();
const express = require('express');
const path = require('path');
const { Client } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const port = 3000;
const ADMIN_EMAIL = "usertest@gmail.com";
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_SUPER_SECRET_STRING_HERE';

// --- JWT Implementation ---
function jwtEncode(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = crypto.createHmac('sha256', secret).update(signingInput).digest('base64url');
    return `${signingInput}.${signature}`;
}
function jwtDecode(token, secret) {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    if (!signature) throw new Error('Invalid token');
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const expectedSignature = crypto.createHmac('sha256', secret).update(signingInput).digest('base64url');
    if (signature !== expectedSignature) throw new Error('Signature verification failed');
    return JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
}

const cryptoData = [ { id: 'BTC', price: 68138.50 }, { id: 'ETH', price: 3557.18 }, { id: 'SOL', price: 152.88 }, { id: 'BNB', price: 610.43 }, { id: 'XRP', price: 0.5234 }, { id: 'ADA', price: 0.4621 }, { id: 'DOGE', price: 0.1572 }, { id: 'SHIB', price: 0.0000281 }, { id: 'DOT', price: 7.25 }, { id: 'LINK', price: 18.50 }, { id: 'LTC', price: 85.12 }, { id: 'MATIC', price: 0.725 }, { id: 'UNI', price: 11.43 }];
const stockData = [ { id: 'AAPL', price: 214.29 }, { id: 'GOOGL', price: 179.22 }, { id: 'MSFT', price: 449.78 }, { id: 'AMZN', price: 189.08 }, { id: 'TSLA', price: 183.01 }, { id: 'NVDA', price: 131.88 }, { id: 'META', price: 498.50 }, { id: 'JPM', price: 198.20 }, { id: 'V', price: 275.40 }, { id: 'WMT', price: 67.50 }, { id: 'NFLX', price: 686.12 }, { id: 'DIS', price: 102.50 }];


app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const client = new Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

client.connect().then(() => console.log('Connected to PostgreSQL')).catch(err => console.error('Connection error', err.stack));

const checkAdmin = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).send('Unauthorized');
        const decoded = jwtDecode(token, JWT_SECRET);
        if (decoded.email !== ADMIN_EMAIL) return res.status(403).send('Forbidden');
        req.user = decoded;
        next();
    } catch (error) { return res.status(401).send('Invalid token'); }
};

// --- HTML SERVING ROUTES ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing.html'));
});

app.get('/app', (req, res) => {
    res.sendFile(path.join(__dirname, 'app.html'));
});

// --- API ROUTES ---
app.post('/register', async (req, res) => {
    const { name, surname, email, phoneNumber, password } = req.body;
    if (!name || !surname || !email || !phoneNumber || !password) return res.status(400).send('All fields are required.');
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userQuery = 'INSERT INTO users (name, surname, email, phone_number, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id';
        const userResult = await client.query(userQuery, [name, surname, email, phoneNumber, hashedPassword]);
        const newUserId = userResult.rows[0].id;
        const defaultPortfolio = [ { id: 'BTC', amount: 0.05 }, { id: 'ETH', amount: 1.5 }, { id: 'AAPL', amount: 10 }, { id: 'TSLA', amount: 5 } ];
        await client.query('INSERT INTO portfolios (user_id, assets) VALUES ($1, $2)', [newUserId, JSON.stringify(defaultPortfolio)]);
        res.status(201).send('User registered successfully');
    } catch (err) { res.status(500).send('Error registering user: ' + (err.detail || err.message)); }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(400).send('User not found');
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (isMatch) {
            const payload = { userId: user.id, email: user.email, name: user.name };
            const token = jwtEncode(payload, JWT_SECRET);
            res.status(200).json({ token: token });
        } else { res.status(400).send('Invalid password'); }
    } catch (err) { res.status(500).send('Database error during login.'); }
});

app.get('/users', checkAdmin, async (req, res) => {
    try {
        const query = `SELECT u.id, u.name, u.surname, u.email, u.phone_number, u.created_at, p.assets FROM users u LEFT JOIN portfolios p ON u.id = p.user_id ORDER BY u.created_at DESC`;
        const result = await client.query(query);
        res.status(200).json(result.rows);
    } catch (err) {
        console.error('Error fetching users with portfolios:', err);
        res.status(500).send('Server error');
    }
});

app.get('/api/portfolio/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const query = `SELECT u.created_at, p.assets FROM users u LEFT JOIN portfolios p ON u.id = p.user_id WHERE u.id = $1`;
        const result = await client.query(query, [userId]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'User not found.' });
        res.status(200).json(result.rows[0]);
    } catch (err) { res.status(500).send('Server error while fetching portfolio.'); }
});

app.post('/api/portfolio/add-funds', checkAdmin, async (req, res) => {
    const { userId, coinId, amountUSD } = req.body;
    if (!userId || !coinId || !amountUSD || parseFloat(amountUSD) <= 0) return res.status(400).send('Valid userId, coinId, and positive amountUSD are required.');
    const allAssets = [...cryptoData, ...stockData];
    const selectedAsset = allAssets.find(c => c.id === coinId);
    if (!selectedAsset) return res.status(400).send('Invalid asset selected.');
    const amountToAdd = parseFloat(amountUSD) / selectedAsset.price;
    try {
        await client.query('BEGIN');
        const { rows } = await client.query('SELECT assets FROM portfolios WHERE user_id = $1 FOR UPDATE', [userId]);
        let currentAssets = (rows.length > 0 && rows[0].assets) ? rows[0].assets : [];
        if(typeof currentAssets === 'string') currentAssets = JSON.parse(currentAssets);
        const existingAssetIndex = currentAssets.findIndex(a => a.id === coinId);
        if (existingAssetIndex > -1) {
            currentAssets[existingAssetIndex].amount = parseFloat(currentAssets[existingAssetIndex].amount) + amountToAdd;
        } else {
            currentAssets.push({ id: coinId, amount: amountToAdd });
        }
        const upsertQuery = `INSERT INTO portfolios (user_id, assets) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET assets = $2;`;
        await client.query(upsertQuery, [userId, JSON.stringify(currentAssets)]);
        await client.query('COMMIT');
        res.status(200).json({ message: 'Funds added successfully!', assets: currentAssets });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error adding funds:', err);
        res.status(500).send('Error adding funds.');
    }
});

app.listen(port, () => { console.log(`Server is running on http://localhost:${port}`); });
