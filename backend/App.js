const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const session = require('express-session');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = 4000;

// PostgreSQL Pool Configuration
const pool = new Pool({
    user: 'postgres.hkkrhwkcjnuccdzrvaeu',
    host: 'aws-0-ap-south-1.pooler.supabase.com',
    database: 'postgres',
    password: 'Kaviswar@123',
    port: 6543
});

const secretKey = "97b34701a945e7d7717fbf4d678f280766a6a64dc7662d7f68318f13d0fe01c085ab970eb17daa8138457f3dac983cd92a6f8e770462ef5ccbfd4d39d9a61bc4";


app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: secretKey,
    resave: false,
    saveUninitialized: true
}));

// User Registration
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO Users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING *',
            [username, email, hashedPassword]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') { // Unique violation error code
            res.status(409).json({ error: 'Username or email already exists' });
        } else {
            res.status(500).json({ error: err.message });
        }
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    try {
        const result = await pool.query('SELECT * FROM Users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (user && await bcrypt.compare(password, user.password_hash)) {
            const token = jwt.sign({ id: user.user_id, username: user.username }, secretKey, { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/api/request-password-reset', async (req, res) => {
    const { username, email } = req.body;
    if (!username || !email) {
        return res.status(400).json({ error: 'Username and email are required' });
    }

    try {
        const result = await pool.query('SELECT * FROM Users WHERE username = $1 AND email = $2', [username, email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // You could generate a reset token here or handle it differently
        res.json({ message: 'Username and email verified. Proceed to reset your password.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/api/reset-password',async (req, res) => {
    const { newPassword } = req.body;

    if (!newPassword) {
        return res.status(400).json({ error: 'New password is required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        // Assuming you have the user ID from the reset process
        const userId = req.userId; // You can store this during the request process or from the session

        await pool.query('UPDATE Users SET password_hash = $1 WHERE user_id = $2', [hashedPassword, userId]);

        res.json({ message: 'Password reset successfully. Please log in with your new password.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/api/income', authenticateToken, async (req, res) => {
    const { amount, description, income_date } = req.body;
    const userId = req.user.id;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Check if balance exists
        const balanceResult = await client.query(
            'SELECT balance FROM Balance WHERE user_id = $1 FOR UPDATE',
            [userId]
        );

        let currentBalance;
        if (balanceResult.rows.length > 0) {
            currentBalance = parseFloat(balanceResult.rows[0].balance);
        } else {
            // Initialize balance if it doesn't exist
            currentBalance = 0.00;
            await client.query(
                'INSERT INTO Balance (user_id, balance) VALUES ($1, $2)',
                [userId, currentBalance]
            );
        }

        const newBalance = currentBalance + parseFloat(amount);

        // Insert new income
        await client.query(
            'INSERT INTO Income (user_id, amount, description, income_date) VALUES ($1, $2, $3, $4)',
            [userId, amount, description, income_date]
        );

        // Update balance
        await client.query(
            'UPDATE Balance SET balance = $1, updated_at = NOW() WHERE user_id = $2',
            [newBalance, userId]
        );

        await client.query('COMMIT');
        res.status(201).json({ message: 'Income added and balance updated successfully' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error adding income:', error);
        res.status(500).json({ error: 'Server error' });
    } finally {
        client.release();
    }
});


// Get user balance
app.get('/api/balance', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const result = await pool.query(
            'SELECT balance FROM Balance WHERE user_id = $1',
            [userId]
        );

        if (result.rows.length > 0) {
            res.json({ balance: result.rows[0].balance });
        } else {
            res.json({ balance: 0.00 });
        }
    } catch (error) {
        console.error('Error fetching balance:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Adding expense
app.post('/api/expenses', authenticateToken, async (req, res) => {
    const { amount, description, expense_date } = req.body;
    const userId = req.user.id;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const balanceResult = await client.query(
            'SELECT balance FROM Balance WHERE user_id = $1 FOR UPDATE',
            [userId]
        );

        const currentBalance = parseFloat(balanceResult.rows[0].balance);
        if (currentBalance < amount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        const newBalance = currentBalance - parseFloat(amount);

        await client.query(
            'INSERT INTO Expenses (user_id, amount, description, expense_date) VALUES ($1, $2, $3, $4)',
            [userId, amount, description, expense_date]
        );

        await client.query(
            'UPDATE Balance SET balance = $1, updated_at = NOW() WHERE user_id = $2',
            [newBalance, userId]
        );

        await client.query('COMMIT');
        res.status(201).json({ message: 'Expense added and balance updated successfully' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error adding expense:', error);
        res.status(500).json({ error: 'Server error' });
    } finally {
        client.release();
    }
});



app.get('/api/recentexpenses', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(
            `SELECT description, amount, expense_date, created_at
            FROM Expenses
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 5`, 
            [userId]
        );

        res.json({ expenses: result.rows });
    } catch (error) {
        console.error('Error fetching recent expenses:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/incomedata', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(`
            SELECT income_date AS date, SUM(amount) AS amount
            FROM Income
            WHERE user_id = $1
            GROUP BY income_date
            ORDER BY income_date ASC
        `, [userId]);

        // Check if data is correct and send it back
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching income data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/api/expensedata', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await pool.query(`
            SELECT expense_date AS date, SUM(amount) AS amount
            FROM Expenses
            WHERE user_id = $1
            GROUP BY expense_date
            ORDER BY expense_date ASC
        `, [userId]);

        // Check if data is correct and send it back
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching expense data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
