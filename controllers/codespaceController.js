const jwt = require('jsonwebtoken');
const pool = require('../config/database');
const { encrypt, decrypt } = require('../utils/encryption');

exports.getCodespace = async (req, res) => {
  try {
    const { slug } = req.params;
    
    // First check if it's in cleanup_logs
    const [deletedLogs] = await pool.query(
      'SELECT * FROM cleanup_logs WHERE deleted_slug = ?',
      [slug]
    );

    if (deletedLogs.length > 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace has expired'
      });
    }
    
    // Get codespace with owner information and check expiration
    const [codespaces] = await pool.query(
      `SELECT c.*, u.username as owner_username,
       (c.owner_id IS NULL AND c.updated_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)) as is_expired
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

    // Check if guest codespace is expired
    if (codespace.is_expired) {
      // Log the deletion first
      await pool.query(
        'INSERT INTO cleanup_logs (deleted_slug) VALUES (?)',
        [slug]
      );
      
      // Then delete the expired codespace
      await pool.query('DELETE FROM codespaces WHERE slug = ?', [slug]);
      
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace has expired'
      });
    }

    // Decrypt content or set default
    if (codespace.content) {
      try {
        codespace.content = decrypt(codespace.content);
      } catch (error) {
        console.error('Decryption error:', error);
        codespace.content = ''; // Fallback to empty if decryption fails
      }
    } else {
      codespace.content = '';
    }

    // For public codespaces - allow immediate access
    if (codespace.access_type === 'public') {
      // Update last activity for guest codespaces
      if (!codespace.owner_id) {
        await pool.query(
          'UPDATE codespaces SET updated_at = CURRENT_TIMESTAMP WHERE slug = ?',
          [slug]
        );
      }
      
      return res.json({
        status: 'success',
        data: codespace
      });
    }

    // Handle private codespaces
    if (codespace.access_type === 'private') {
      const token = req.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return res.status(403).json({
          status: 'fail',
          message: 'Access denied',
          owner: codespace.owner_username
        });
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check owner access
        if (codespace.owner_id === decoded.id) {
          return res.json({
            status: 'success',
            data: codespace
          });
        }

        // Check collaborator access
        const [access] = await pool.query(
          'SELECT * FROM codespace_access WHERE codespace_id = ? AND user_id = ?',
          [codespace.id, decoded.id]
        );

        if (access.length === 0) {
          return res.status(403).json({
            status: 'fail',
            message: 'Access denied',
            owner: codespace.owner_username
          });
        }

        // Access granted for collaborator
        return res.json({
          status: 'success',
          data: codespace
        });

      } catch (error) {
        console.error('Token verification error:', error);
        return res.status(401).json({
          status: 'fail',
          message: 'Invalid or expired token'
        });
      }
    }

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

    // Make sure we're encrypting the content
    const encryptedContent = encrypt(content || '');

    // Get codespace details first
    const [codespaces] = await pool.query(
      'SELECT id, owner_id, access_type FROM codespaces WHERE slug = ?',
      [slug]
    );

    if (codespaces.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace not found'
      });
    }

    const codespace = codespaces[0];

    // For public codespaces, allow updates without token
    if (codespace.access_type === 'public') {
      await pool.query(
        'UPDATE codespaces SET content = ?, language = ? WHERE slug = ?',
        [encryptedContent, language, slug]
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
        message: 'Authentication required'
      });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (codespace.owner_id !== decoded.id) {
        return res.status(403).json({
          status: 'fail',
          message: 'You do not have permission to edit this codespace'
        });
      }
    } catch (error) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid or expired token'
      });
    }

    // Update codespace
    await pool.query(
      'UPDATE codespaces SET content = ?, language = ? WHERE slug = ?',
      [encryptedContent, language, slug]
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
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    const { slug } = req.body;

    // Use SELECT FOR UPDATE to lock the row
    const [existing] = await connection.query(
      'SELECT * FROM codespaces WHERE slug = ? FOR UPDATE',
      [slug]
    );

    // If codespace exists, return it without error
    if (existing.length > 0) {
      await connection.commit();
      return res.json({
        status: 'success',
        data: existing[0],
        message: 'Codespace already exists'
      });
    }

    // Get user ID from token if available
    let owner_id = null;
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      try {
        const decoded = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET);
        owner_id = decoded.id;
      } catch (error) {
        console.log('Token verification failed:', error);
      }
    }

    // Create new codespace
    const encryptedContent = encrypt(''); 
    const [result] = await connection.query(
      `INSERT INTO codespaces (
        slug, owner_id, content, language, access_type, is_public
      ) VALUES (?, ?, ?, ?, ?, ?)`,
      [slug, owner_id, encryptedContent, 'javascript', 'public', true]
    );

    const newCodespace = {
      id: result.insertId,
      slug,
      owner_id,
      content: '',
      language: 'javascript',
      access_type: 'public',
      is_public: true
    };

    await connection.commit();

    return res.status(201).json({
      status: 'success',
      data: newCodespace,
      message: 'Codespace created successfully'
    });

  } catch (error) {
    await connection.rollback();
    
    // If it's a duplicate entry error, try to fetch the existing codespace
    if (error.code === 'ER_DUP_ENTRY') {
      try {
        const [existing] = await connection.query(
          'SELECT * FROM codespaces WHERE slug = ?',
          [req.body.slug]
        );
        
        if (existing.length > 0) {
          return res.json({
            status: 'success',
            data: existing[0],
            message: 'Codespace already exists'
          });
        }
      } catch (secondaryError) {
        console.error('Error fetching existing codespace:', secondaryError);
      }
    }

    console.error('Error creating codespace:', error);
    return res.status(500).json({
      status: 'error',
      message: 'Failed to create codespace'
    });
  } finally {
    connection.release();
  }
};