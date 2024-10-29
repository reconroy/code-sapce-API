const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const codespaceController = require('../controllers/codespaceController');

// Protected routes
router.get('/:slug', authMiddleware, codespaceController.getCodespace);
router.put('/:slug', authMiddleware, codespaceController.updateCodespace);

module.exports = router;