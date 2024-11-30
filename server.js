const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const cors = require('cors');
const diffRoute = require('./routes/diffRoute');
const authController = require('./controllers/authController');
const pool = require('./config/database');
const authMiddleware = require('./middleware/authMiddleware');
const codespaceRoutes = require('./routes/codespace');
const authRoutes = require('./routes/auth');
const { encrypt, decrypt, validateKey } = require('./utils/encryption');
const setupWebSocketHandlers = require('./websocket/handlers');
const swaggerUi = require('swagger-ui-express');
const swaggerSpecs = require('./config/swagger');

require('dotenv').config();

const app = express();
const server = http.createServer(app);

// CORS middleware setup
app.use(cors({
  origin: process.env.FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
}));

// Additional middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
//fot the index file in public
// app.use(express.static(path.join(__dirname, 'public')));

// Socket.IO setup with CORS
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL ,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
  },
  transports: ['websocket', 'polling']
});
// Setup WebSocket handlers
setupWebSocketHandlers(io);
// Make io accessible throughout the app
app.set('io', io);

// Enable preflight requests
app.options('*', cors());

// Headers middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.FRONTEND_URL );
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const port = process.env.PORT || 5000;

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/codespace', codespaceRoutes);
app.use('/api/diff', diffRoute);
app.get('/api/users/count', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT COUNT(*) as count FROM users');
    res.json({ count: result[0].count });
  } catch (error) {
    console.error('Error getting user count:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to get user count'
    });
  }
});

// Auth endpoints
app.post('/api/login', authController.login);
app.post('/api/register', authController.register);
app.get('/api/check-username/:username', authController.checkUsername);
app.get('/api/check-email/:email', authController.checkEmail);
app.post('/api/send-otp', authController.sendOTP);
app.post('/api/verify-otp', authController.verifyOTP);
app.post('/api/reset-password', authController.resetPassword);
app.post('/api/change-password', authMiddleware, authController.changePassword);

// Socket connection handling
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

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

  socket.on('joinUserSpace', (userId) => {
    if (userId) {
      socket.join(`user_${userId}`);
      console.log(`User ${userId} joined their personal space`);
    }
  });

  socket.on('codespaceUpdated', ({ userId, codespace }) => {
    io.to(`user_${userId}`).emit('codespaceSettingsChanged', codespace);
  });

  socket.on('codespaceDeleted', ({ userId, slug }) => {
    io.to(`user_${userId}`).emit('codespaceRemoved', slug);
  });

  socket.on('codeChange', async ({ slug, content }) => {
    try {
      const encryptedContent = encrypt(content);
      await pool.query('UPDATE codespaces SET content = ? WHERE slug = ?', [encryptedContent, slug]);
      io.to(slug).emit('codeUpdate', content); // Send unencrypted content to clients
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
    console.log('Client disconnected:', socket.id);
  });
});

/**
 * @swagger
 * /api/codespace/{slug}:
 *   get:
 *     tags: [Codespace]
 *     summary: Get a codespace by slug with access control
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Codespace found successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     slug:
 *                       type: string
 *                     content:
 *                       type: string
 *                     language:
 *                       type: string
 *                     owner_id:
 *                       type: integer
 *                     owner_username:
 *                       type: string
 *                     access_type:
 *                       type: string
 *                       enum: [public, private, shared]
 *                     is_default:
 *                       type: boolean
 *       403:
 *         description: Access denied
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: fail
 *                 message:
 *                   type: string
 *                 owner:
 *                   type: string
 *       404:
 *         description: Codespace not found
 */
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

/**
 * @swagger
 * /api/codespace/{slug}:
 *   put:
 *     tags: [Codespace]
 *     summary: Update a codespace content and language
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               content:
 *                 type: string
 *               language:
 *                 type: string
 *     responses:
 *       200:
 *         description: Codespace updated successfully
 *       500:
 *         description: Internal server error
 */

// Add these lines BEFORE the catch-all routes (around line 281)
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs));

// Root route to redirect to Swagger
app.get('/', (req, res) => {
  res.redirect('/api-docs');
});

// Then the catch-all routes should come after
app.use('/api/*', (req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Not found' });
});

// Add this before starting the server
if (!validateKey()) {
    console.error('Invalid encryption key length. Please check your ENCRYPTION_KEY in .env');
    process.exit(1);
}

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
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

/**
 * @swagger
 * tags:
 *   name: Users
 *   description: User management endpoints
 * 
 * /api/users/count:
 *   get:
 *     tags: [Users]
 *     summary: Get total number of users
 *     responses:
 *       200:
 *         description: Returns the total count of users
 * 
 * /api/users/current:
 *   get:
 *     tags: [Users]
 *     summary: Get current user details
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Current user details retrieved successfully
 * 
 * /api/users/default-codespace:
 *   get:
 *     tags: [Users]
 *     summary: Get user's default codespace
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Default codespace retrieved successfully
 */

/**
 * @swagger
 * /api/codespace:
 *   post:
 *     tags: [Codespace]
 *     summary: Create a new codespace or get existing one
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - slug
 *             properties:
 *               slug:
 *                 type: string
 *               content:
 *                 type: string
 *               language:
 *                 type: string
 *                 default: javascript
 *     responses:
 *       200:
 *         description: Codespace created or existing one returned
 *         content:
 *           application/json:
 *             schema:
 *               oneOf:
 *                 - type: object
 *                   properties:
 *                     message:
 *                       type: string
 *                     slug:
 *                       type: string
 *                 - type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     slug:
 *                       type: string
 *                     content:
 *                       type: string
 *                     language:
 *                       type: string
 *       500:
 *         description: Internal server error
 */

/**
 * @swagger
 * /api/users/count:
 *   get:
 *     tags: [Users]
 *     summary: Get total number of registered users
 *     responses:
 *       200:
 *         description: Returns the total count of users
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 count:
 *                   type: integer
 *                   example: 42
 *       500:
 *         description: Server error
 */
