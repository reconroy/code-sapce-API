const jwt = require('jsonwebtoken');
const pool = require('../config/database');

// Add the getCodespace function that was missing
exports.getCodespace = async (req, res) => {
    const { slug } = req.params;
    const userId = req.user.id; // From auth middleware
  
    try {
      // Get codespace with owner information first
      const [codespaces] = await pool.query(
        `SELECT c.*, u.username as owner_username 
         FROM codespaces c 
         LEFT JOIN users u ON c.owner_id = u.id 
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
      if (codespace.access_type === 'private') {
        // Check if user is the owner
        if (codespace.owner_id !== userId) {
          // Check if user has explicit access
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
        }
      }
  
      res.json({
        status: 'success',
        data: codespace
      });
    } catch (error) {
      console.error('Error in getCodespace:', error);
      res.status(500).json({
        status: 'error',
        message: 'Server error'
      });
    }
  };
  
  exports.updateCodespace = async (req, res) => {
    try {
      const { slug } = req.params;
      const { content, language } = req.body;
  
      // Get codespace details first
      const [codespace] = await pool.query(
        'SELECT owner_id, access_type FROM codespaces WHERE slug = ?',
        [slug]
      );
  
      if (codespace.length === 0) {
        return res.status(404).json({
          status: 'fail',
          message: 'Codespace not found'
        });
      }
  
      // For public codespaces, allow updates without token
      if (codespace[0].access_type === 'public') {
        await pool.query(
          'UPDATE codespaces SET content = ?, language = ? WHERE slug = ?',
          [content, language, slug]
        );
        return res.json({
          status: 'success',
          message: 'Codespace updated successfully'
        });
      }
  
      // For private codespaces, verify token and ownership
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(401).json({
          status: 'fail',
          reason: 'unauthorized',
          message: 'Authentication required'
        });
      }
  
      // Verify ownership for private codespaces
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (codespace[0].owner_id !== decoded.id) {
        return res.status(403).json({
          status: 'fail',
          reason: 'unauthorized',
          message: 'You do not have permission to edit this private codespace'
        });
      }
  
      // Update codespace
      await pool.query(
        'UPDATE codespaces SET content = ?, language = ? WHERE slug = ?',
        [content, language, slug]
      );
  
      res.json({
        status: 'success',
        message: 'Codespace updated successfully'
      });
    } catch (error) {
      console.error('Update codespace error:', error);
      res.status(500).json({
        status: 'fail',
        message: 'Failed to update codespace'
      });
    }
  };

exports.createCodespace = async (req, res) => {
    try {
      const { slug } = req.body;
  
      // First check if codespace exists
      const [existingCodespace] = await pool.query(
        'SELECT * FROM codespaces WHERE slug = ?',
        [slug]
      );
  
      if (existingCodespace.length > 0) {
        return res.status(400).json({
          status: 'fail',
          message: 'A codespace with this slug already exists'
        });
      }
  
      // Get user ID from token
      let owner_id = null;
      const authHeader = req.headers.authorization;
      
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET);
          owner_id = decoded.id;
        } catch (error) {
          console.error('Token verification failed:', error);
        }
      }
  
      // Create new codespace
      const [result] = await pool.query(
        `INSERT INTO codespaces (
          slug,
          owner_id,
          content,
          language,
          is_public,
          is_default,
          access_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          slug,
          owner_id,        // Set the owner_id from token
          '',             // empty initial content
          'javascript',   // default language
          true,          // public by default
          false,         // not a default codespace
          'public'       // public access type
        ]
      );
  
      res.status(201).json({
        status: 'success',
        data: {
          id: result.insertId,
          slug,
          owner_id,
          is_public: true,
          access_type: 'public'
        }
      });
    } catch (error) {
      console.error('Error creating codespace:', error);
      res.status(500).json({
        status: 'error',
        message: 'Failed to create codespace'
      });
    }
  };

  exports.updateCodespace = async (req, res) => {
    try {
      const { slug } = req.params;
      const { content, language } = req.body;
  
      // Get codespace details first
      const [codespace] = await pool.query(
        'SELECT owner_id, is_private FROM codespaces WHERE slug = ?',
        [slug]
      );
  
      if (codespace.length === 0) {
        return res.status(404).json({
          status: 'fail',
          message: 'Codespace not found'
        });
      }
  
      // For public codespaces, allow updates without token
      if (!codespace[0].is_private) {
        await pool.query(
          'UPDATE codespaces SET content = ?, language = ? WHERE slug = ?',
          [content, language, slug]
        );
        return res.json({
          status: 'success',
          message: 'Codespace updated successfully'
        });
      }
  
      // For private codespaces, verify token and ownership
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(401).json({
          status: 'fail',
          reason: 'unauthorized',
          message: 'Authentication required'
        });
      }
  
      // Verify ownership for private codespaces
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (codespace[0].owner_id !== decoded.id) {
        return res.status(403).json({
          status: 'fail',
          reason: 'unauthorized',
          message: 'You do not have permission to edit this private codespace'
        });
      }
  
      // Update codespace
      await pool.query(
        'UPDATE codespaces SET content = ?, language = ? WHERE slug = ?',
        [content, language, slug]
      );
  
      res.json({
        status: 'success',
        message: 'Codespace updated successfully'
      });
    } catch (error) {
      console.error('Update codespace error:', error);
      res.status(500).json({
        status: 'fail',
        message: 'Failed to update codespace'
      });
    }
  };