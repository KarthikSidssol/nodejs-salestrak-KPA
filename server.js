require('dotenv').config();
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
// const upload = multer({ dest: 'uploads/' });
const path = require('path');
const fs = require('fs');
// const aws = require('aws-sdk');
const multerS3 = require('multer-s3');

const { S3Client } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');


const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

// const storage = multer.diskStorage({
//   destination: 'uploads/',
//   filename: (req, file, cb) => {
//     const ext = path.extname(file.originalname);
//     cb(null, `doc_${Date.now()}${ext}`);
//   }
// });
// const upload = multer({ storage });

const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: 'salestrak-pa',
    acl: 'private',
    contentType: multerS3.AUTO_CONTENT_TYPE,    
    metadata: function (req, file, cb) {
      cb(null, { fieldName: file.fieldname });
    },
    key: function (req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase();
      const allowedExtensions = ['.pdf', '.jpg', '.jpeg', '.png', '.xls', '.xlsx']; 
      
      if (!allowedExtensions.includes(ext)) {
        return cb(new Error('Invalid file extension'));
      }
      
      const filename = `doc_${Date.now()}${ext}`;
      cb(null, filename);
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/pdf',
      'image/jpeg',
      'image/png',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ];
    cb(null, allowedTypes.includes(file.mimetype));
  }
});



const app = express();
const PORT = process.env.PORT || 5001;

app.use(bodyParser.json());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(cookieParser());

app.use(cors({
  origin: ['http://localhost:3000','http://pa.salestrak.in'],
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
      { userId: user.id, email: user.email, name: user.acc_name, ph_no: user.mobile },
      process.env.ACCESS_TOKEN
    );

    // Set cookie (optional)
    res.cookie('session-token', token, {
      httpOnly: true,
      secure: false, // ✅ false for localhost, true in production with HTTPS
      sameSite: 'Lax' // ✅ Lax or None (None if using cross-site with HTTPS)
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

app.post('/forgotPassword', async (req, res) => {
  try {
    const { email, password , newPassword} = req.body;

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
      return res.status(404).json({ error: 'Email not registered' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update password in the DB
    await req.db.query(
      'update cus_mas set password = ? where email = ?',
      [hashedPassword, email]
    );

    res.json({ message: 'Password updated successfully' });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/me', authenticationToken, (req, res) => {
  console.log("authenticationToken",req.userDetails);
  res.json({
    message: 'User data',
    user: req.userDetails
  });
});

function authenticationToken(req, res, next) {
  const token = req.cookies['session-token']; 
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN, (err, userDetails) => {
    if (err) return res.sendStatus(403);
    req.userDetails = userDetails;
    next();
  });
}

app.post('/logOut', (req, res) => {
  res.clearCookie('session-token', {
    httpOnly: true,
    secure: false, // true if using HTTPS
    sameSite: 'Lax', // 'None' if secure=true and cross-origin
    // sameSite: 'Lax',
  });
  res.status(200).json({ message: 'Logout successful' });
});


app.get('/Header',authenticationToken , async (req, res) => {
  try {
    const accId = req.userDetails.userId;
    const [rows] = await req.db.query(`select h.id as id,h.acc_id, h.header_name from header as h
      where h.acc_id = ?`, [accId]);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching headers:', error);
    res.status(500).json({ error: 'Failed to fetch headers' });
  }
});

app.post('/addHeader', authenticationToken, async (req, res) => {
  try {
    const { name } = req.body;
    console.log('Adding header:', req.body);
    if (!name || name.trim() === '') {
      return res.status(400).json({ error: 'Header name is required' });
    }

    const accId = req.userDetails.userId;

    const [existing] = await req.db.query(
      'SELECT id FROM header WHERE header_name = ? AND acc_id = ?',
      [name.trim(), accId]
    );

    if (existing.length > 0) {
      return res.status(409).json({ error: 'Header name already exists' });
    }

    const [result] = await req.db.query(
      'insert into header (header_name, acc_id) VALUES (?, ?)',
      [name, accId]
    );

    res.status(201).json({
      message: 'Header added successfully',
      header: {
        id: result.insertId,
        name,
        acc_id: accId
      }
    });
  } catch (error) {
    console.error('Error adding header:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/addItems', authenticationToken, async (req, res) => {
  try {
    const { header_id, header_name, title, short_desc, det_desc, highlights , updatedHeaderId ,updatedItemId } = req.body;
    const accId = req.userDetails.userId;

    if (!header_id || !header_name || !title) {
      return res.status(400).json({ error: 'Header ID, Header Name, and Title are required' });
    }

    if (updatedHeaderId) {
      // Update existing item
      await req.db.query(
        `UPDATE item_mas
         SET header_id = ?, header_name = ?, title = ?, short_desc = ?, det_desc = ?, highlights = ?
         WHERE id = ? AND acc_id = ?`,
        [header_id, header_name, title, short_desc, det_desc, highlights, updatedItemId, accId]
      );
      return res.status(200).json({ message: 'Item updated successfully' });
    }else{
      const [result] = await req.db.query(
        `INSERT INTO item_mas 
        (acc_id, header_id, header_name, title, short_desc, det_desc, highlights, create_dt)
        VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
        [accId, header_id, header_name, title, short_desc, det_desc, highlights]
      );

      res.status(201).json({
        message: 'Item added successfully',
        item_id: result.insertId,
        header_id
      });
    }

  } catch (error) {
    console.error('Error adding item:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/getItemByHeaderId', authenticationToken, async (req, res) => {
  try {
    const { headerId , itemId } = req.body;
    const accId = req.userDetails.userId;

    const [rows] = await req.db.query(
      `select id, header_id, title, short_desc, det_desc, highlights
       from item_mas
       where header_id = ? and id = ? AND acc_id = ?`,
      [headerId, itemId, accId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Item not found' });
    }

    const [reminderRows] = await req.db.query(
      `select id, item_id, reminder_name, DATE_FORMAT(reminder_date,'%d-%m-%Y') AS reminder_date, alert_before
       from reminder_mas
       where item_id = ? and acc_id = ?`,
      [itemId, accId]
    );

    const [documentRows] = await req.db.query(
      `select id, item_id, doc_name, doc_file , renewal_req
      from doc_mas
      where item_id = ? and acc_id = ?`,
      [itemId, accId]
    );

    res.json({ item: rows[0], reminders: reminderRows, documents: documentRows });
  } catch (error) {
    console.error('Error fetching item by header ID:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/addReminder', authenticationToken, async (req, res) => {
  try {
    const accId = req.userDetails.userId;
    const { header_id, item_id , name, date, before } = req.body;

    if (!header_id || !name || !date) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Insert into remainder_mas table
    await req.db.query(
      `insert into reminder_mas (acc_id, item_id, reminder_name, reminder_date, alert_before)
       VALUES (?, ?, ?, ?, ?)`,
      [accId, item_id, name, date, before]
    );

    return res.status(201).json({ message: 'Reminder added successfully' });

  } catch (error) {
    console.error('Error adding reminder:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/editReminder/:id', authenticationToken, async (req, res) => {
  const { id } = req.params;
  const accId = req.userDetails.userId;

  try {
    const [rows] = await req.db.query(
      "select id, reminder_name, DATE_FORMAT(reminder_date,'%Y-%m-%d') AS reminder_date, alert_before from reminder_mas where id = ? AND acc_id = ?",
      [id, accId]
    );

    if (rows.length === 0) return res.status(404).json({ error: 'Reminder not found' });
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching reminder:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add this route to your backend (server.js)
app.delete('/deleteItem/:id', authenticationToken, async (req, res) => {
  try {
    const itemId = req.params.id;
    const accId = req.userDetails.userId;

    // First verify the item belongs to the user
    const [itemCheck] = await req.db.query(
      'select id from item_mas where id = ? and acc_id = ?',
      [itemId, accId]
    );

    if (itemCheck.length === 0) {
      return res.status(404).json({ error: 'Item not found or not authorized' });
    }

    // Start transaction
    await req.db.query('START TRANSACTION');

    try {
      // Delete associated reminders first
      await req.db.query(
        'delete from reminder_mas where item_id = ? and acc_id = ?',
        [itemId, accId]
      );

      // Delete associated documents
      await req.db.query(
        'delete from doc_mas where item_id = ? and acc_id = ?',
        [itemId, accId]
      );

      // Finally delete the item itself
      await req.db.query(
        'delete from item_mas where id = ? and acc_id = ?',
        [itemId, accId]
      );

      // Commit transaction if all queries succeeded
      await req.db.query('COMMIT');

      res.status(200).json({ message: 'Item and all associated data deleted successfully' });
    } catch (error) {
      // Rollback transaction if any error occurs
      await req.db.query('ROLLBACK');
      throw error; // Re-throw to be caught by outer catch
    }
  } catch (error) {
    console.error('Error deleting item:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.delete('/deleteReminder/:id', authenticationToken, async (req, res) => {
  try {
    const reminderId = req.params.id;
    const accId = req.userDetails.userId;

    const [reminderCheck] = await req.db.query(
      'select id from reminder_mas where id = ? and acc_id = ?',
      [reminderId, accId]
    );

    if (reminderCheck.length === 0) {
      return res.status(404).json({ 
        error: 'Reminder not found or not authorized' 
      });
    }

    await req.db.query(
      'delete from reminder_mas where id = ? and acc_id = ?',
      [reminderId, accId]
    );

    res.status(200).json({ 
      message: 'Reminder deleted successfully' 
    });

  } catch (error) {
    console.error('Error deleting reminder:', error);
    res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

// Add this route to your backend (server.js)
app.put('/updateReminder/:id', authenticationToken, async (req, res) => {
  try {
    const reminderId = req.params.id;
    const accId = req.userDetails.userId;
    const { name, date, before } = req.body;
    // Validate required fields
    if (!name || !date) {
      return res.status(400).json({ 
        error: 'All fields (name, date) are required' 
      });
    }

    // First verify the reminder belongs to the user
    const [reminderCheck] = await req.db.query(
      'select id from reminder_mas where id = ? and acc_id = ?',
      [reminderId, accId]
    );

    if (reminderCheck.length === 0) {
      return res.status(404).json({ 
        error: 'Reminder not found or not authorized' 
      });
    }

    // Update the reminder
    await req.db.query(
      `update reminder_mas 
       set reminder_name = ?, reminder_date = ?, alert_before = ?
       where id = ? and acc_id = ?`,
      [name, date, before, reminderId, accId]
    );

    res.status(200).json({ 
      message: 'Reminder updated successfully',
      updatedReminder: {
        id: reminderId,
        name,
        date,
        before
      }
    });

  } catch (error) {
    console.error('Error updating reminder:', error);
    res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

app.post('/addDocument', authenticationToken, upload.single('doc_file'), async (req, res) => {
  try {
    const { doc_name, item_id } = req.body;
    const doc_file = req.file;
    const accId = req.userDetails.userId;

    if (!doc_name || !item_id || !doc_file) {
      return res.status(400).json({ error: 'Document name, item ID, and file are required' });
    }

    const [result] = await req.db.query(
      `insert into doc_mas 
       (acc_id, item_id, doc_name, doc_file) 
       values (?, ?, ?, ?)`,
      [accId, item_id, doc_name, doc_file.key] 
    );

    res.status(201).json({
      message: 'Document uploaded successfully',
      document: {
        id: result.insertId,
        name: doc_name,
        file: doc_file.key
      }
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Failed to upload document' });
  }
});


app.put('/updateDocument/:id', authenticationToken, upload.single('doc_file'), async (req, res) => {
  try {
    const docId = req.params.id;
    const accId = req.userDetails.userId;
    const { doc_name } = req.body; // item_id shouldn't be needed for update
    const newFile = req.file;

    // 1. Verify document exists and belongs to user
    const [currentDoc] = await req.db.query(
      `SELECT doc_file FROM doc_mas WHERE id = ? AND acc_id = ?`,
      [docId, accId]
    );

    if (currentDoc.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    // 2. Start transaction
    await req.db.query('START TRANSACTION');

    try {
      let finalFileKey = currentDoc[0].doc_file;

      // 3. If new file was uploaded
      if (newFile) {
        // Delete old file from S3
        await s3.send(new DeleteObjectCommand({
          Bucket: 'salestrak-pa',
          Key: currentDoc[0].doc_file
        }));

        // Use the new file's key
        finalFileKey = newFile.key;
      }

      // 4. Update database record
      await req.db.query(
        `UPDATE doc_mas 
         SET doc_name = ?, doc_file = ?
         WHERE id = ? AND acc_id = ?`,
        [doc_name, finalFileKey, docId, accId]
      );

      await req.db.query('COMMIT');
      res.json({ message: 'Document updated successfully' });

    } catch (error) {
      await req.db.query('ROLLBACK');
      throw error;
    }

  } catch (error) {
    console.error('Update document error:', error);
    res.status(500).json({ error: 'Failed to update document' });
  }
});

app.get('/downloadDocument/:id', authenticationToken, async (req, res) => {
  try {
    const docId = req.params.id;
    const accId = req.userDetails.userId;

    // 1. Verify document exists and belongs to user
    const [doc] = await req.db.query(
      `select doc_name, doc_file 
       from doc_mas 
       where id = ? AND acc_id = ?`,
      [docId, accId]
    );

    if (doc.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const document = doc[0];

    // const params = {
    //   Bucket: 'salestrak-pa',
    //   Key: document.doc_file_path,
    //   Expires: 300 // 5 minutes
    // };

    // const url = s3.getSignedUrl('getObject', params);
    // res.json({ downloadUrl: url });

    const command = new GetObjectCommand({ 
      Bucket: 'salestrak-pa',
      Key: document.doc_file
    });

    const url = await getSignedUrl(s3, command, { expiresIn: 300 });
    res.redirect(url);

  } catch (error) {
    console.error('Download document error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/deleteDocument/:id', authenticationToken, async (req, res) => {
  try {
    const docId = req.params.id;
    const accId = req.userDetails.userId;

    const [doc] = await req.db.query(
      `select doc_file from doc_mas where id = ? AND acc_id = ?`,
      [docId, accId]
    );

    if (doc.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const s3Key = doc[0].doc_file; // This should be the S3 object key

    // 2. Start transaction
    await req.db.query('START TRANSACTION');

    try {
      // 3. Delete from database
      await req.db.query(
        `delete from doc_mas where id = ? and acc_id = ?`,
        [docId, accId]
      );

      // 4. Delete from S3
      await s3.send(new DeleteObjectCommand({
        Bucket: 'salestrak-pa',
        Key: s3Key
      }));

      await req.db.query('COMMIT');
      res.json({ message: 'Document deleted successfully' });

    } catch (error) {
      await req.db.query('ROLLBACK');
      throw error;
    }

  } catch (error) {
    console.error('Delete document error:', error);
    res.status(500).json({ error: 'Failed to delete document' });
  }
});


app.get('/download/:id', authenticationToken, async (req, res) => {
  try {
    // 1. Verify user has access to this document
    const [doc] = await req.db.query(
      `SELECT doc_file, doc_name FROM doc_mas WHERE id = ? AND acc_id = ?`,
      [req.params.id, req.userDetails.userId]
    );
    
    if (!doc.length) return res.status(404).json({ error: 'Document not found' });

    // 2. Generate pre-signed URL (expires in 5 minutes)
    const url = await getSignedUrl(s3, new GetObjectCommand({
      Bucket: 'salestrak-pa',
      Key: doc[0].doc_file,
      ResponseContentDisposition: `attachment; filename="${doc[0].doc_file}"`
    }), { expiresIn: 300 });

    // 3. Redirect to the S3 URL
    res.redirect(url);

  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ error: 'Download failed' });
  }
});


app.get('/getAllItemData', authenticationToken, async (req, res) => {
  try {
    const accId = req.userDetails.userId;

    const [headers] = await req.db.query(
      'select id, header_name FROM header where acc_id = ?',
      [accId]
    );

    if (headers.length === 0) {
      return res.json({ headers: [], items: [] });
    }

    // Get all items for these headers
    const [items] = await req.db.query(
      `select id, header_id, header_name, title, short_desc 
       from item_mas 
       where acc_id = ? 
       order by id desc`,
      [accId]
    );

    const result = headers.map(header => ({
      header_id: header.id,
      header_name: header.header_name,
      items: items.filter(item => item.header_id === header.id)
    }));

    res.json(result);

  } catch (error) {
    console.error('Error fetching all item data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/getAllremainderDate', authenticationToken, async (req, res) => {
  try {
    const accId = req.userDetails.userId;

    // Get all reminders with their associated item info
    const [reminders] = await req.db.query(
      `SELECT 
          r.id, 
          r.item_id, 
          i.title AS item_title,
          i.header_name,i.header_id,
          r.reminder_name,
          DATE_FORMAT(r.reminder_date, '%Y-%m-%d') AS reminder_date,
          rm.remind_me_name as alert_before
        FROM reminder_mas r
        LEFT JOIN item_mas i ON r.item_id = i.id
        LEFT JOIN remind_me rm ON r.alert_before = rm.id
        WHERE r.acc_id = ?
          AND (
            (r.alert_before = 1 AND CURRENT_DATE >= DATE_SUB(r.reminder_date, INTERVAL 1 DAY)) OR
            (r.alert_before = 2 AND CURRENT_DATE >= DATE_SUB(r.reminder_date, INTERVAL 1 WEEK)) OR
            (r.alert_before = 3 AND CURRENT_DATE >= DATE_SUB(r.reminder_date, INTERVAL 15 DAY)) OR
            (r.alert_before = 4 AND CURRENT_DATE >= DATE_SUB(r.reminder_date, INTERVAL 1 MONTH))
          )
        ORDER BY r.id ASC`,
      [accId]
    );

    res.json(reminders);

  } catch (error) {
    console.error('Error fetching all reminders:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/getAllDocumentData', authenticationToken, async (req, res) => {
  try {
    const accId = req.userDetails.userId;

    // Get all documents with their associated item info
    const [documents] = await req.db.query(
      `select d.id, d.acc_id,d.item_id,d.doc_name,d.doc_file ,im.title
      from doc_mas d 
      left outer join item_mas as im on im.id = d.item_id
      where d.acc_id = ? order by id limit 5`,
      [accId]
    );
    res.json(documents);

  } catch (error) {
    console.error('Error fetching all documents:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/remindMeName', async (req, res) => {
  try {
    const [rows] = await req.db.query(`select id , remind_me_name from remind_me
      where status = 0`);
      res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch headers' });
  }
});

app.get('/searchDocuments', authenticationToken, async (req, res) => {
  try {
    const { term } = req.query;
    const accId = req.userDetails.userId;

    const [results] = await req.db.query(
      `select id, doc_name, doc_file 
       FROM doc_mas 
       WHERE acc_id = ? AND doc_name LIKE ?`,
      [accId, `%${term}%`]
    );

    res.json(results || []);
  } catch (error) {
    console.error('Document search error:', error);
    res.status(500).json([]);
  }
});

app.get('/searchItems', authenticationToken, async (req, res) => {
  try {
    const { term } = req.query;
    const accId = req.userDetails.userId;

    const [results] = await req.db.query(
      `SELECT id, title, short_desc, header_id 
       FROM item_mas 
       WHERE acc_id = ? AND title LIKE ?`,
      [accId, `%${term}%`]
    );

    res.json(results || []);
  } catch (error) {
    console.error('Item search error:', error);
    res.status(500).json([]);
  }
});
