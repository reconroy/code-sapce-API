const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const codespaceController = require('../controllers/codespaceController');

// Public routes
router.get('/:slug', codespaceController.getCodespace);
router.post('/', codespaceController.createCodespace);

// Protected routes
router.put('/:slug', authMiddleware, codespaceController.updateCodespace);

router.get('/user/codespaces', authMiddleware, codespaceController.getUserCodespaces);
module.exports = router;