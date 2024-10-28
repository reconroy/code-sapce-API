const jwt = require('jsonwebtoken');
const pool = require('../config/database');

// Add the getCodespace function that was missing
exports.getCodespace = async (req, res) => {
  const { slug } = req.params;
  let userId = null;

  try {
    // Get user ID from token if exists
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      userId = decoded.id;
    }

    // Get codespace with owner information
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

    // Only check access for default/private codespaces
    if (codespace.is_default) {
      if (codespace.owner_id !== userId) {
        return res.status(403).json({
          status: 'fail',
          message: 'Access denied',
          owner: codespace.owner_username
        });
      }
    }

    res.json(codespace);
  } catch (error) {
    console.error('Error fetching codespace:', error);
    res.status(500).json({
      status: 'error',
      message: 'Server error'
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