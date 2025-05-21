const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const jwt = require('jsonwebtoken');
require('dotenv').config();


const app = express();
app.use(cors());
app.use(bodyParser.json());

// Secret key for JWT (put this in your .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_here';

// Connect to MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    ca: fs.readFileSync('./ca.pem')
  }
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL Connected...');
});

// Helper function to verify JWT token inside route handlers
function verifyToken(req, res) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    res.status(401).json({ message: 'Authorization header missing' });
    return null;
  }
  const token = authHeader.split(' ')[1]; // Bearer <token>
  if (!token) {
    res.status(401).json({ message: 'Token missing' });
    return null;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded; // return decoded payload if valid
  } catch (err) {
    res.status(403).json({ message: 'Invalid or expired token' });
    return null;
  }
}

// Register user (no token needed)
app.post('/register', async (req, res) => {
  const { full_name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    'INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
    [full_name, email, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Registration failed' });
      res.json({ message: 'User registered successfully' });
    }
  );
});

// Login user and return JWT token
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  
  console.log('Login attempt for:', email);
  
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    
    console.log('Query results:', results);
    
    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = results[0];
    try {
      const isMatch = await bcrypt.compare(password, user.password);
      
      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid email or password' });
      }

      // Create JWT token valid for 1 hour
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

      res.json({
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          full_name: user.full_name,
          email: user.email
        }
      });
    } catch (error) {
      console.error('Bcrypt error:', error);
      return res.status(500).json({ error: 'Authentication error' });
    }
  });
});


// Protected: Get all products
app.get('/products', (req, res) => {
  const user = verifyToken(req, res);
  if (!user) return; // verification failed

  db.query('SELECT * FROM products', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

// Protected: Get product by id
app.get('/products/:id', (req, res) => {
  const user = verifyToken(req, res);
  if (!user) return;

  const { id } = req.params;
  db.query('SELECT * FROM products WHERE id = ?', [id], (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(404).json({ message: 'Product not found' });
    res.json(results[0]);
  });
});

// Protected: Add new product
app.post('/products', (req, res) => {
  const user = verifyToken(req, res);
  if (!user) return;

  const { name, price, image_url, category } = req.body;
  db.query(
    'INSERT INTO products (name, price, image_url, category) VALUES (?, ?, ?, ?)',
    [name, price, image_url, category],
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json({ message: 'Product added successfully' });
    }
  );
});

// Protected: Update product
app.put('/products/:id', (req, res) => {
  const user = verifyToken(req, res);
  if (!user) return;

  const { id } = req.params;
  const { name, price, image_url, category } = req.body;

  // Added WHERE clause here, which was missing before
  db.query(
    'UPDATE products SET name = ?, price = ?, image_url = ?, category = ? WHERE id = ?',
    [name, price, image_url, category, id],
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json({ message: 'Product updated successfully' });
    }
  );
});

// Protected: Delete product
app.delete('/products/:id', (req, res) => {
  const user = verifyToken(req, res);
  if (!user) return;

  const { id } = req.params;
  db.query('DELETE FROM products WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json({ message: 'Product deleted successfully' });
  });
});

const PORT = process.env.PORT || 3000;

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
