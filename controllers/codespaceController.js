const jwt = require('jsonwebtoken');
const pool = require('../config/database');
const { encrypt, decrypt } = require('../utils/encryption');

exports.getCodespace = async (req, res) => {
  try {
    const { slug } = req.params;
    const userId = req.user?.id;

    const [codespaces] = await pool.query(
      `SELECT c.*, u.username as owner_username,
        CASE 
          WHEN c.access_type = 'public' THEN true
          WHEN c.owner_id = ? THEN true
          WHEN c.access_type = 'shared' AND EXISTS (
            SELECT 1 FROM codespace_access 
            WHERE codespace_id = c.id AND user_id = ?
          ) THEN true
          ELSE false
        END as hasAccess
       FROM codespaces c
       LEFT JOIN users u ON c.owner_id = u.id
       WHERE c.slug = ?`,
      [userId, userId, slug]
    );

    if (codespaces.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace not found'
      });
    }

    const codespace = codespaces[0];

    // Decrypt the content before sending
    if (codespace.content) {
      try {
        codespace.content = decrypt(codespace.content);
      } catch (error) {
        console.error('Error decrypting content:', error);
        codespace.content = ''; // Fallback to empty string if decryption fails
      }
    }

    // Always include hasAccess in the response
    return res.json({
      status: 'success',
      data: {
        ...codespace,
        hasAccess: codespace.hasAccess || codespace.owner_id === userId
      }
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

exports.getUserCodespaces = async (req, res) => {
  try {
    const userId = req.user.id;

    const [codespaces] = await pool.query(
      `SELECT 
        c.*, 
        u.username as owner_username
      FROM codespaces c
      JOIN users u ON c.owner_id = u.id
      WHERE c.owner_id = ?
      ORDER BY c.is_default DESC, c.created_at DESC`,
      [userId]
    );

    res.json({
      status: 'success',
      data: codespaces
    });

  } catch (error) {
    console.error('Error fetching user codespaces:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch codespaces'
    });
  }
};

exports.checkSlugAvailability = async (req, res) => {
  try {
    const { slug } = req.params;
    const [existing] = await pool.query(
      'SELECT id FROM codespaces WHERE slug = ?',
      [slug]
    );
    
    res.json({
      status: 'success',
      available: existing.length === 0
    });
  } catch (error) {
    console.error('Error checking slug availability:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to check slug availability'
    });
  }
};

exports.updateCodespaceSettings = async (req, res) => {
  try {
    const { slug } = req.params;
    const { newSlug, accessType, passkey, isArchived } = req.body;
    const userId = req.user.id;

    // First get the specific codespace
    const [codespaces] = await pool.query(
      'SELECT id, owner_id, is_default FROM codespaces WHERE slug = ? AND owner_id = ?',
      [slug, userId]
    );

    if (codespaces.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace not found'
      });
    }

    const codespace = codespaces[0];

    // Update only this specific codespace
    const updateQuery = `
      UPDATE codespaces 
      SET 
        slug = ?,
        access_type = ?,
        passkey = ?,
        is_archived = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND owner_id = ?
    `;

    const updateValues = [
      newSlug || slug,
      accessType,
      passkey || null,
      isArchived || false,
      codespace.id,
      userId
    ];

    const [result] = await pool.query(updateQuery, updateValues);

    if (result.affectedRows === 0) {
      throw new Error('Failed to update codespace');
    }

    // Fetch the updated codespace to verify changes
    const [updatedCodespace] = await pool.query(
      'SELECT * FROM codespaces WHERE id = ? AND owner_id = ?',
      [codespace.id, userId]
    );

    // Emit socket event with the specific codespace data
    if (req.app.get('io')) {
      req.app.get('io').to(`user_${userId}`).emit('codespaceSettingsChanged', {
        id: codespace.id,
        slug: newSlug || slug,
        access_type: accessType,
        is_archived: isArchived || false,
        hasPasskey: !!passkey
      });
    }

    res.json({
      status: 'success',
      message: 'Codespace settings updated successfully',
      data: updatedCodespace[0]
    });

  } catch (error) {
    console.error('Error updating codespace settings:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update codespace settings',
      details: error.message
    });
  }
};

exports.deleteCodespace = async (req, res) => {
  try {
    const { slug } = req.params;
    const userId = req.user.id;

    // Verify ownership
    const [codespace] = await pool.query(
      'SELECT owner_id FROM codespaces WHERE slug = ?',
      [slug]
    );

    if (codespace.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace not found'
      });
    }

    if (codespace[0].owner_id !== userId) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to delete this codespace'
      });
    }

    await pool.query('DELETE FROM codespaces WHERE slug = ?', [slug]);

    // Emit websocket event
    req.app.get('io').to(`user_${userId}`).emit('codespaceRemoved', slug);

    res.json({
      status: 'success',
      message: 'Codespace deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting codespace:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete codespace'
    });
  }
};

exports.getAccessLogs = async (req, res) => {
  try {
    const { slug } = req.params;
    const userId = req.user.id;

    // First verify if user is the owner
    const [codespaces] = await pool.query(
      'SELECT id, owner_id FROM codespaces WHERE slug = ?',
      [slug]
    );

    if (codespaces.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace not found'
      });
    }

    const codespace = codespaces[0];

    if (codespace.owner_id !== userId) {
      return res.status(403).json({
        status: 'fail',
        message: 'Only the owner can view access logs'
      });
    }

    // Get access logs with user information
    const [accessLogs] = await pool.query(
      `SELECT u.username, ca.created_at as access_granted_at
       FROM codespace_access ca
       JOIN users u ON ca.user_id = u.id
       WHERE ca.codespace_id = ?
       ORDER BY ca.created_at DESC`,
      [codespace.id]
    );

    console.log('Access logs found:', accessLogs); // Debug log

    res.json({
      status: 'success',
      data: accessLogs
    });

  } catch (error) {
    console.error('Error getting access logs:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to get access logs'
    });
  }
};

exports.verifyPasskey = async (req, res) => {
  try {
    const { slug } = req.params;
    const { passkey } = req.body;
    const userId = req.user.id;

    // Get codespace details
    const [codespaces] = await pool.query(
      'SELECT id, owner_id, passkey FROM codespaces WHERE slug = ?',
      [slug]
    );

    if (codespaces.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'Codespace not found'
      });
    }

    const codespace = codespaces[0];

    // Verify passkey
    if (codespace.passkey !== passkey) {
      return res.status(403).json({
        status: 'fail',
        message: 'Invalid passkey'
      });
    }

    // Grant access by adding to codespace_access table
    await pool.query(
      'INSERT INTO codespace_access (codespace_id, user_id) VALUES (?, ?)',
      [codespace.id, userId]
    );

    res.json({
      status: 'success',
      message: 'Access granted successfully'
    });

  } catch (error) {
    console.error('Error verifying passkey:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to verify passkey'
    });
  }
};