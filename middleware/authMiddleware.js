const jwt = require('jsonwebtoken');
const pool = require('../config/database');

const authMiddleware = async (req, res, next) => {
  try {
    // For codespace routes, check if it's public first
    if (req.params.slug) {
      const [codespaces] = await pool.query(
        'SELECT access_type FROM codespaces WHERE slug = ?',
        [req.params.slug]
      );

      // If codespace is public, allow access without authentication
      if (codespaces.length > 0 && codespaces[0].access_type === 'public') {
        return next();
      }
    }

    // For private codespaces and other protected routes
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        status: 'fail',
        message: 'No token provided' 
      });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: decoded.id };
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({ 
      status: 'fail',
      message: 'Authentication failed' 
    });
  }
};

module.exports = authMiddleware;