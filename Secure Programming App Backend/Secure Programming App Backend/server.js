require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const http = require('http');
const { Server } = require('socket.io');
const { encrypt, decrypt } = require('./utils/crypto');
const validator = require('validator');
const xss = require('xss');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);

const db = new sqlite3.Database('./chatApp.db', (err) => {
    if (err) console.error('DB connection failed:', err.message);
    else console.log('Connected to SQLite');
});

// DB setup
db.serialize(() => {
  // Create users table if not exists
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  )`);

  // Create messages table if not exists
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
  )`);
});

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const ADMIN_SIGNUP_CODE = process.env.ADMIN_SIGNUP_CODE || 'secret-admin-code-123';

// Enable CORS with credentials
const corsOptions = {
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'], // React frontend URLs
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Security & body parsing
app.use(helmet());
app.use(bodyParser.json());
app.use(cookieParser());

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 5 login attempts per windowMs
  message: {
    message: 'Too many login attempts, please try again after 15 minutes'
  }
});

// Rate limiting for all other routes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5000 // increased from 100 to 1000 requests per 15 minutes
});

// Apply rate limiting
app.use('/signin', loginLimiter);
app.use('/signup', loginLimiter);
app.use('/messages', apiLimiter);

// Socket.IO with CORS
const io = new Server(server, {
  cors: corsOptions
});

// JWT middleware with better error handling
function authenticateJWT(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ 
      message: 'Access denied',
      isExpired: true,
      redirectTo: '/login'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired',
          isExpired: true,
          redirectTo: '/login'
        });
      }
      return res.status(403).json({ 
        message: 'Invalid token',
        isExpired: true,
        redirectTo: '/login'
      });
    }
    req.user = user;
    next();
  });
}

// Admin middleware
function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false,
      message: 'Admin access required' 
    });
  }
  next();
}

// Input validation middleware
function validateInput(req, res, next) {
  if (req.body.message) {
    // Only sanitize message for XSS, no length restriction
    req.body.message = xss(validator.escape(req.body.message));
  }
  
  if (req.body.email) {
    if (!validator.isEmail(req.body.email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    req.body.email = validator.normalizeEmail(req.body.email);
  }

  if (req.body.username) {
    req.body.username = xss(validator.escape(req.body.username));
    if (!validator.isLength(req.body.username, { min: 3, max: 30 })) {
      return res.status(400).json({ message: 'Username must be between 3-30 characters' });
    }
  }

  next();
}

app.post('/signup', validateInput, async (req, res) => {
    const { username, email, password, adminCode } = req.body;
    console.log('Signup attempt:', { username, email, adminCode }); // Log signup attempt

    if (!username || !email || !password)
      return res.status(400).json({ message: 'All fields required' });

    const role = adminCode === ADMIN_SIGNUP_CODE ? 'admin' : 'user';
    console.log('Assigned role:', role); // Log assigned role
  
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, emailRow) => {
      if (err) {
        console.error('Email check error:', err); // Log email check error
        return res.status(500).json({ message: 'Error checking user' });
      }
      if (emailRow) return res.status(400).json({ message: 'Email already registered' });

      db.get("SELECT * FROM users WHERE username = ?", [username], async (err, usernameRow) => {
        if (err) {
          console.error('Username check error:', err); // Log username check error
          return res.status(500).json({ message: 'Error checking username' });
        }
        if (usernameRow) return res.status(400).json({ message: 'Username already taken' });
        
        try {
          const hashedPassword = await bcrypt.hash(password, 10);
          
          db.run("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            [username, email, hashedPassword, role], function (err) {
              if (err) {
                console.error('Insert error:', err); // Log insert error
                return res.status(500).json({ message: 'Error creating user', error: err.message });
              }
      
              const token = jwt.sign({ userId: this.lastID, username, email, role }, JWT_SECRET, {
                expiresIn: '1h'
              });
      
              res.status(201).json({
                message: role === 'admin' ? 'Admin created successfully' : 'User created successfully',
                token,
                role,
                redirectTo: '/chat',
              });
            });
        } catch (err) {
          console.error('Password hash error:', err); // Log password hash error
          return res.status(500).json({ message: 'Error creating user' });
        }
      });
    });
  });

// Signin
app.post('/signin', (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, row) => {
    if (err) return res.status(500).json({ message: 'Internal error' });
    if (!row) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, row.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { 
        userId: row.id, 
        email: row.email,
        username: row.username,
        role: row.role  // Include role in token
      }, 
      JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Set secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
    });

    res.json({ 
      message: 'Login successful',
      token,
      user: {
        id: row.id,
        email: row.email,
        username: row.username,
        role: row.role  // Added role here
      },
      redirectTo: '/chat'
    });
  });
});

// Get messages
app.get('/messages', (req, res) => {
  const query = `SELECT messages.message, messages.timestamp, users.username 
                 FROM messages JOIN users ON messages.userId = users.id 
                 ORDER BY messages.timestamp ASC`;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching messages' });
    
    const decryptedRows = rows.map(row => {
      try {
        return {
          ...row,
          message: decrypt(row.message)
        };
      } catch (error) {
        return {
          ...row,
          message: 'Message encryption error'
        };
      }
    });
    
    res.json(decryptedRows);
  });
});

// Post a message
app.post('/messages', [authenticateJWT, validateInput], (req, res, next) => {
  const { message } = req.body;
  console.log(req.body);
  if (!message || message.trim() === '') {
    return res.status(400).json({ 
      success: false,
      message: 'Message cannot be empty or contain only whitespace' 
    });
  }

  try {
    const encryptedMessage = encrypt(message);
    
    db.run("INSERT INTO messages (userId, message) VALUES (?, ?)", 
      [req.user.userId, encryptedMessage], 
      function (err) {
        if (err) {
          // Log error internally but don't expose details
          console.error('Database error:', err);
          return next({
            status: 500,
            publicMessage: 'Failed to save message',
            error: err // Only logged server-side
          });
        }

        io.emit('newMessage', { 
          message, 
          username: req.user.username || req.user.email 
        });
        
        res.status(201).json({ 
          success: true,
          message: 'Message sent'
        });
      }
    );
  } catch (error) {
    // Log encryption errors internally
    console.error('Internal error:', error);
    next({
      status: 500,
      publicMessage: 'Message processing failed',
      error: error // Only logged server-side
    });
  }
});

// Clear chat
app.delete('/clearchat', [authenticateJWT, isAdmin], (req, res) => {
  db.get("SELECT COUNT(*) as count FROM messages", [], (err, row) => {
    if (err) return res.status(500).json({ message: 'Error counting messages' });
    
    const messageCount = row.count;
    
    db.run("DELETE FROM messages;", [], function (err) {
      if (err) return res.status(500).json({ message: 'Failed to delete messages' });
      
      // Emit socket event to notify all users
      io.emit('chatCleared', {
        clearedBy: req.user.username,
        messageCount: messageCount
      });

      res.status(200).json({ 
        success: true,
        message: 'Chat cleared successfully',
        messagesDeleted: messageCount,
        clearedBy: req.user.username,
        timestamp: new Date().toISOString()
      });
    });
  });
});

// Clear chat
app.post('/clearUsers', (req, res) => {
    db.run("DELETE FROM users;", [], function (err) {
      if (err) return res.status(500).json({ message: 'Failed to delete users' });
      res.status(201).json({ message: 'Users cleared' });
    });
  });

app.get('/users',(req,res) => {
    let query = "SELECT * from users;";

    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ message: 'Error fetching messages' });
        res.json(rows);
      });
})

// Check token validity
app.get('/verify-token', (req, res) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ 
      valid: false,
      message: 'No token provided',
      redirectTo: '/login'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          valid: false,
          message: 'Token expired',
          redirectTo: '/login'
        });
      }
      return res.status(401).json({
        valid: false,
        message: 'Invalid token',
        redirectTo: '/login'
      });
    }

    res.json({
      valid: true,
      user: decoded
    });
  });
});

// Get all users with details (admin only)
app.get('/admin/users', [authenticateJWT, isAdmin], (req, res) => {
  const query = "SELECT id, username, email, role FROM users";
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error fetching users' });
    res.json(rows);
  });
});

// Update user role (admin only)
app.patch('/admin/users/:userId/role', [authenticateJWT, isAdmin], (req, res) => {
  const { role } = req.body;
  const { userId } = req.params;

  if (!role || !['user', 'admin'].includes(role)) {
    return res.status(400).json({ message: 'Invalid role specified' });
  }

  db.run("UPDATE users SET role = ? WHERE id = ?", [role, userId], function(err) {
    if (err) return res.status(500).json({ message: 'Error updating user role' });
    if (this.changes === 0) return res.status(404).json({ message: 'User not found' });
    
    res.json({ 
      success: true, 
      message: 'User role updated successfully' 
    });
  });
});

// Delete all non-admin users (admin only)
app.delete('/admin/users/non-admin', [authenticateJWT, isAdmin], (req, res) => {
  db.run("DELETE FROM users WHERE role != 'admin'", function(err) {
    if (err) return res.status(500).json({ message: 'Error deleting users' });
    
    res.json({ 
      success: true,
      message: 'All non-admin users deleted successfully',
      usersDeleted: this.changes
    });
  });
});

// Error handling middleware
function errorHandler(err, req, res, next) {
  // Log full error details server-side
  console.error('Error details:', {
    error: err.error,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  // Send sanitized response to client
  res.status(err.status || 500).json({
    success: false,
    message: err.publicMessage || 'An unexpected error occurred'
  });
}

// Add error middleware
app.use(errorHandler);

// Socket.IO
io.on('connection', (socket) => {
  console.log('User connected');

  socket.on('message', (message) => {
    // Broadcast to all users including sender (optional) or excluding sender
    socket.broadcast.emit('message', message); // sends to everyone except sender
    // or use io.emit('message', message); to send to everyone including sender
  });

  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;