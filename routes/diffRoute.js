const express = require('express');
const calculateDiff = require('../services/diffService');
const router = express.Router();

router.post('/', (req, res) => {
  const { original, modified } = req.body;
  try {
    const diffResult = calculateDiff(original, modified);
    res.json(diffResult);
  } catch (error) {
    console.error('Error calculating diff:', error);
    res.status(500).json({ error: 'Error calculating diff' });
  }
});

module.exports = router;