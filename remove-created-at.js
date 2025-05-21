const mysql = require('mysql2');
const fs = require('fs');
require('dotenv').config();

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
  if (err) {
    console.error('Error connecting to database:', err);
    process.exit(1);
  }
  console.log('MySQL Connected...');
  
  // Show users table structure
  db.query('DESCRIBE users', (err, results) => {
    if (err) {
      console.error('Error describing users table:', err);
    } else {
      console.log('Users table structure:');
      console.table(results);
    }
    
    // Show products table structure
    db.query('DESCRIBE products', (err, results) => {
      if (err) {
        console.error('Error describing products table:', err);
      } else {
        console.log('Products table structure:');
        console.table(results);
      }
      
      db.end();
    });
  });
});
