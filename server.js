require('dotenv').config();
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5002;

app.use(bodyParser.json());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cookieParser());

app.use(cors({
  origin: ['http://localhost:3000'],
  credentials: true
}));

// MySQL config
const dbConfig = {
  host: process.env.DB_HOST || process.env.DB_SERVER,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Create a connection pool
const pool = mysql.createPool(dbConfig);

// Test the connection
pool.getConnection()
  .then(connection => {
    console.log('Connected to MySQL database');
    connection.release(); // Release the connection back to the pool
    
    // Start the server only after DB connects
    app.listen(PORT, () => {
      console.log(`🚀 Server is running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('DB connection failed:', err.message);
    process.exit(1); // Exit if DB connection fails
  });

// Make the pool available in your routes
app.use((req, res, next) => {
  req.db = pool;
  next();
});

// Routes
app.get('/api', (req, res) => {
  res.send('Welcome to Node.js API Project');
});


app.post('/register', async (req, res) => {
  try {
    const { name, email, password, mobile } = req.body;
    console.log('Registration data:', req.body);
    if (!name || !email || !password || !mobile) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if email already exists
    const [existingUser] = await req.db.query(
      'select * from cus_mas where email = ?', 
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({ error: 'Email already exists' });
    }

     if (!/^\d{10}$/.test(mobile)) {
      return res.status(400).json({ error: 'Mobile must be exactly 10 digits' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insert new user
    const [result] = await req.db.query(
      `insert into cus_mas 
       (acc_name, email, password, mobile, status, create_dt) 
       VALUES (?, ?, ?, ?, 1, NOW())`,
      [name, email, hashedPassword, mobile]
    );

    res.status(201).json({ 
      message: 'Registration successful',
      userId: result.insertId 
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user by email
    const [users] = await req.db.query(
      'select * from cus_mas where email = ? and status = 1',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.ACCESS_TOKEN,
      { expiresIn: '1h' }
    );

    // Set cookie (optional)
    res.cookie('session-token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000 // 1 hour
    });

    res.json({ 
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.acc_name,
        email: user.email,
        mobile: user.mobile
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

