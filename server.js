const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const cors = require('cors');
const diffRoute = require('./routes/diffRoute');
const authController = require('./controllers/authController');
const pool = require('./config/database');
const authMiddleware = require('./middleware/authMiddleware');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());
const port = process.env.PORT || 5000;

app.post('/api/login', authController.login);
// Handle user registration
app.post('/api/register', authController.register);

// Check if username is available
app.get('/api/check-username/:username', authController.checkUsername);

// Check if email is available
app.get('/api/check-email/:email', authController.checkEmail);

// Handle OTP
app.post('/api/send-otp', authController.sendOTP);
app.post('/api/verify-otp', authController.verifyOTP);

// Handle password reset
app.post('/api/reset-password', authController.resetPassword);
app.post('/api/change-password', authMiddleware, authController.changePassword);

app.use('/api/diff', diffRoute);

io.on('connection', (socket) => {
  console.log('New client connected');

  socket.on('joinRoom', async (slug) => {
    try {
      console.log(`Client joining room: ${slug}`);
      
      // Check if the room (codespace) exists in the database
      const [rows] = await pool.query('SELECT * FROM codespaces WHERE slug = ?', [slug]);
      
      if (rows.length === 0) {
        // If the codespace doesn't exist, create it
        await pool.query('INSERT INTO codespaces (slug, content, language) VALUES (?, ?, ?)', [slug, '', 'javascript']);
        console.log(`Created new codespace: ${slug}`);
      }
      
      // Join the room
      socket.join(slug);
      console.log(`Client joined room: ${slug}`);
      
      // Emit a success event back to the client
      socket.emit('roomJoined', { slug, message: 'Successfully joined the room' });
    } catch (error) {
      console.error(`Error joining room ${slug}:`, error);
      socket.emit('roomError', { slug, message: 'Failed to join the room' });
    }
  });

  socket.on('codeChange', async ({ slug, content }) => {
    try {
      console.log(`Code change in room ${slug}`);
      await pool.query('UPDATE codespaces SET content = ? WHERE slug = ?', [content, slug]);
      io.to(slug).emit('codeUpdate', content);
    } catch (error) {
      console.error('Error saving code:', error);
    }
  });

  socket.on('selectionChange', ({ slug, selection }) => {
    console.log(`Selection change in room ${slug}`);
    socket.to(slug).emit('selectionUpdate', { selection });
  });

  socket.on('clearSelection', ({ slug }) => {
    console.log(`Selection cleared in room ${slug}`);
    socket.to(slug).emit('clearSelection');
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

app.get('/api/codespace/:slug', async (req, res) => {
  const { slug } = req.params;
  try {
    console.log('Fetching codespace for slug:', slug);
    const [rows] = await pool.query('SELECT * FROM codespaces WHERE slug = ?', [slug]);
    if (rows.length > 0) {
      console.log('Codespace found:', rows[0]);
      res.json(rows[0]);
    } else {
      console.log('Codespace not found');
      res.status(404).json({ error: 'Codespace not found' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.post('/api/codespace', async (req, res) => {
  const { slug, content, language } = req.body;
  try {
    // First, check if the codespace already exists
    const [existingCodespace] = await pool.query('SELECT * FROM codespaces WHERE slug = ?', [slug]);
    
    if (existingCodespace.length > 0) {
      // If it exists, return the existing codespace
      console.log('Codespace already exists:', existingCodespace[0]);
      res.json(existingCodespace[0]);
    } else {
      // If it doesn't exist, create a new one
      await pool.query('INSERT INTO codespaces (slug, content, language) VALUES (?, ?, ?)', [slug, content || '', language || 'javascript']);
      console.log('New codespace created:', { slug, content, language });
      res.json({ message: 'Codespace created', slug });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.put('/api/codespace/:slug', async (req, res) => {
  const { slug } = req.params;
  const { content, language } = req.body;
  try {
    console.log('Updating codespace:', { slug, content, language });
    await pool.query('UPDATE codespaces SET content = ?, language = ? WHERE slug = ?', [content, language, slug]);
    res.json({ message: 'Codespace updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.use(express.static(path.join(__dirname, 'dist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
// ... existing code ...

app.get('/api/codespace/:slug', async (req, res) => {
  const { slug } = req.params;
  let userId = null;

  // Get user ID if token exists
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      userId = decoded.id;
    }
  } catch (error) {
    // Invalid token, continue as guest
  }

  try {
    // Get codespace with owner information
    const [codespaces] = await pool.query(
      `SELECT c.*, u.username as owner_username 
       FROM codespaces c 
       JOIN users u ON c.owner_id = u.id 
       WHERE c.slug = ?`,
      [slug]
    );

    if (codespaces.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace not found'
      });
    }

    const codespace = codespaces[0];

    // Check access permissions
    if (codespace.access_type === 'private' || codespace.is_default) {
      // Check if user is the owner
      if (codespace.owner_id !== userId) {
        // Check if user has explicit access
        if (userId) {
          const [access] = await pool.query(
            'SELECT * FROM codespace_access WHERE codespace_id = ? AND user_id = ?',
            [codespace.id, userId]
          );
          
          if (access.length === 0) {
            return res.status(403).json({
              status: 'fail',
              message: 'Access denied',
              owner: codespace.owner_username
            });
          }
        } else {
          // Guest user, no access
          return res.status(403).json({
            status: 'fail',
            message: 'Access denied',
            owner: codespace.owner_username
          });
        }
      }
    }

    // User has access, return codespace data
    res.json({
      status: 'success',
      data: codespace
    });
  } catch (error) {
    console.error('Error fetching codespace:', error);
    res.status(500).json({
      status: 'error',
      message: 'Server error'
    });
  }
});