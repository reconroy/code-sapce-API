const express = require('express');
const router = express.Router();
const codespaceController = require('../controllers/codespaceController');

// Make sure these controller functions exist
router.get('/:slug', codespaceController.getCodespace);
router.post('/', codespaceController.createCodespace);

module.exports = router;