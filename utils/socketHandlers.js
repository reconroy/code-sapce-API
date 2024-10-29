const pool = require('../config/db');

const socketHandlers = (io) => {
  io.on('connection', (socket) => {
    console.log('New client connected');

    socket.on('join-room', (room) => {
      console.log('Client joining room:', room);
      socket.join(room);
      console.log('Client joined room:', room);
    });

    socket.on('code-update', async ({ room, content }) => {
      try {
        // Broadcast the change to all clients in the room except sender
        socket.to(room).emit('code-update', content);
        
        // Update the database
        await pool.query(
          'UPDATE codespaces SET content = ? WHERE slug = ?',
          [content, room]
        );
      } catch (error) {
        console.error('Socket code update error:', error);
        socket.emit('error', 'Failed to save changes');
      }
    });

    socket.on('disconnect', () => {
      console.log('Client disconnected');
    });
  });
};

module.exports = socketHandlers;