const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(bodyParser.json());

// MySQL Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'auth_project'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
    } else {
        console.log('Connected to the database!');
    }
});

// Email Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Routes
// 1. Registration Endpoint
app.post('/register', async (req, res) => {
    const { firstName, lastName, email, password, role } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            'INSERT INTO users (firstName, lastName, email, password, role, verified) VALUES (?, ?, ?, ?, ?, ?)',
            [firstName, lastName, email, hashedPassword, role, false],
            (err, result) => {
                if (err) return res.status(500).send(err);

                // Send verification email
                const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1d' });
                const verifyUrl = `http://localhost:${PORT}/verify?token=${token}`;

                transporter.sendMail({
                    from: process.env.EMAIL,
                    to: email,
                    subject: 'Verify Your Email',
                    html: `<p>Click <a href="${verifyUrl}">here</a> to verify your email.</p>`
                });

                res.status(200).send('Registration successful. Please verify your email.');
            }
        );
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// 2. Email Verification Endpoint
app.get('/verify', (req, res) => {
    const { token } = req.query;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const { email } = decoded;

        db.query('UPDATE users SET verified = true WHERE email = ?', [email], (err, result) => {
            if (err) return res.status(500).send(err);
            res.send('Email verified successfully.');
        });
    } catch (error) {
        res.status(400).send('Invalid or expired token.');
    }
});

// 3. Admin Login Endpoint
app.post('/admin/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ? AND role = "admin"', [email], async (err, results) => {
        if (err) return res.status(500).send(err);

        if (results.length === 0) return res.status(403).send('You are not allowed to login from here.');

        const user = results[0];

        if (!user.verified) return res.status(403).send('Please verify your email first.');

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.status(401).send('Invalid credentials.');

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
    });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));