const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/authMiddleware');
const codespaceController = require('../controllers/codespaceController');

// Public routes
router.get('/:slug', codespaceController.getCodespace);
router.post('/', codespaceController.createCodespace);
router.get('/check-slug/:slug', codespaceController.checkSlugAvailability);

// Protected routes - make sure authMiddleware is before the route handler
router.put('/:slug/settings', authMiddleware, codespaceController.updateCodespaceSettings);
router.delete('/:slug', authMiddleware, codespaceController.deleteCodespace);
router.get('/user/codespaces', authMiddleware, codespaceController.getUserCodespaces);

module.exports = router;