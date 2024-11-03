const { encrypt } = require('../utils/encryption');
const pool = require('../config/database');

function setupWebSocketHandlers(io) {
  io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('joinRoom', async (slug) => {
      try {
        console.log(`Client joining room: ${slug}`);
        
        const [rows] = await pool.query('SELECT * FROM codespaces WHERE slug = ?', [slug]);
        
        if (rows.length === 0) {
          await pool.query(
            'INSERT INTO codespaces (slug, content, language) VALUES (?, ?, ?)', 
            [slug, '', 'javascript']
          );
          console.log(`Created new codespace: ${slug}`);
        }
        
        socket.join(slug);
        console.log(`Client joined room: ${slug}`);
        
        socket.emit('roomJoined', { 
          slug, 
          message: 'Successfully joined the room' 
        });
      } catch (error) {
        console.error(`Error joining room ${slug}:`, error);
        socket.emit('roomError', { 
          slug, 
          message: 'Failed to join the room' 
        });
      }
    });

    socket.on('joinUserSpace', (userId) => {
      if (userId) {
        socket.join(`user_${userId}`);
        console.log(`User ${userId} joined their personal space`);
      }
    });

    socket.on('codespaceUpdated', ({ userId, codespace }) => {
      console.log('Broadcasting codespace update:', codespace);
      io.to(`user_${userId}`).emit('codespaceSettingsChanged', codespace);
    });

    socket.on('codespaceDeleted', ({ userId, codespaceId, slug }) => {
      console.log('Broadcasting codespace deletion:', { id: codespaceId, slug });
      io.to(`user_${userId}`).emit('codespaceRemoved', { id: codespaceId, slug });
    });

    socket.on('codeChange', async ({ slug, content }) => {
      try {
        const encryptedContent = encrypt(content);
        await pool.query(
          'UPDATE codespaces SET content = ? WHERE slug = ?', 
          [encryptedContent, slug]
        );
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
      console.log('Client disconnected:', socket.id);
    });
  });
}

module.exports = setupWebSocketHandlers;
