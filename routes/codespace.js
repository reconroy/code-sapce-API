const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const authMiddleware = require('../middleware/authMiddleware');
const codespaceController = require('../controllers/codespaceController');

// Public routes
router.get('/:slug', codespaceController.getCodespace);
router.post('/', codespaceController.createCodespace);
router.get('/check-slug/:slug', codespaceController.checkSlugAvailability);

// Protected routes - make sure authMiddleware is before the route handler
router.put('/:slug/settings', authMiddleware, codespaceController.updateCodespaceSettings);
router.delete('/:slug', authMiddleware, codespaceController.deleteCodespace);
router.get('/user/codespaces', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const [codespaces] = await pool.query(
      `SELECT 
        c.*, 
        u.username as owner_username
      FROM codespaces c
      JOIN users u ON c.owner_id = u.id
      WHERE c.owner_id = ?
      ORDER BY 
        c.is_default DESC,
        CASE WHEN c.is_default = 1 THEN NULL ELSE c.updated_at END DESC`,
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
      message: 'Failed to fetch codespaces',
      error: error.message
    });
  }
});

module.exports = router;