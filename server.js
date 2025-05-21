const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Add these new imports
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'E-Commerce API',
      version: '1.0.0',
      description: 'E-Commerce API Documentation',
      contact: {
        name: 'API Support',
        email: 'support@example.com',
      },
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./server.js'], // Path to the API docs
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));


// Secret key for JWT (put this in your .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_here';

// Connect to MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    ca: fs.readFileSync('./ca.pem')
  },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const promisePool = pool.promise();

// Test the connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection error:', err);
    return;
  }
  console.log('MySQL Connected...');
  connection.release(); // Release the connection immediately
});

// Helper function to verify JWT token inside route handlers
function verifyToken(req, res) {
  try {
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

    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      res.status(401).json({ message: 'Token expired' });
    } else if (err.name === 'JsonWebTokenError') {
      res.status(403).json({ message: 'Invalid token' });
    } else {
      res.status(500).json({ message: 'Authentication error' });
    }
    return null;
  }
}


/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - full_name
 *               - email
 *               - password
 *             properties:
 *               full_name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: User registered successfully
 *       500:
 *         description: Registration failed
 */
// Register user (no token needed)
app.post('/register', async (req, res) => {
  const { full_name, email, password } = req.body;
  
  console.log('Registration attempt for:', email);
  
  if (!full_name || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Use the pool instead of a single connection
    pool.query(
      'INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
      [full_name, email, hashedPassword],
      (err, result) => {
        if (err) {
          console.error('Registration error:', err);
          return res.status(500).json({ error: 'Registration failed', details: err.message });
        }
        res.json({ message: 'User registered successfully' });
      }
    );
  } catch (error) {
    console.error('Hashing error:', error);
    return res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});


/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login a user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 token:
 *                   type: string
 *                 user:
 *                   type: object
 *       401:
 *         description: Invalid email or password
 *       500:
 *         description: Server error
 */

// Login user and return JWT token
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  
  console.log('Login attempt for:', email);
  
  // Use the pool instead of a single connection
  pool.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
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



/**
 * @swagger
 * /products:
 *   get:
 *     summary: Get all products
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all products
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   name:
 *                     type: string
 *                   price:
 *                     type: number
 *                   image_url:
 *                     type: string
 *                   category:
 *                     type: string
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */


// Protected: Get all products
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  
  console.log('Login attempt for:', email);
  
  // Use the pool instead of a single connection
  pool.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
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



/**
 * @swagger
 * /products/{id}:
 *   get:
 *     summary: Get a product by ID
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Product ID
 *     responses:
 *       200:
 *         description: Product details
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Product not found
 *       500:
 *         description: Server error
 */

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


/**
 * @swagger
 * /products:
 *   post:
 *     summary: Add a new product
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - price
 *             properties:
 *               name:
 *                 type: string
 *               price:
 *                 type: number
 *               image_url:
 *                 type: string
 *               category:
 *                 type: string
 *     responses:
 *       200:
 *         description: Product added successfully
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */

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

/**
 * @swagger
 * /products/{id}:
 *   put:
 *     summary: Update a product
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Product ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               price:
 *                 type: number
 *               image_url:
 *                 type: string
 *               category:
 *                 type: string
 *     responses:
 *       200:
 *         description: Product updated successfully
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */

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

/**
 * @swagger
 * /products/{id}:
 *   delete:
 *     summary: Delete a product
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Product ID
 *     responses:
 *       200:
 *         description: Product deleted successfully
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */

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


/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - full_name
 *         - email
 *         - password
 *       properties:
 *         id:
 *           type: integer
 *           description: Auto-generated ID
 *         full_name:
 *           type: string
 *         email:
 *           type: string
 *           format: email
 *         password:
 *           type: string
 *           format: password
 *         created_at:
 *           type: string
 *           format: date-time
 *     Product:
 *       type: object
 *       required:
 *         - name
 *         - price
 *       properties:
 *         id:
 *           type: integer
 *           description: Auto-generated ID
 *         name:
 *           type: string
 *         price:
 *           type: number
 *           format: float
 *         image_url:
 *           type: string
 *         category:
 *           type: string
 *         created_at:
 *           type: string
 *           format: date-time
 */
const PORT = process.env.PORT || 3000;

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

