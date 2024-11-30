const express = require('express');
const calculateDiff = require('../services/diffService');
const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Diff
 *   description: Code difference comparison endpoints
 * 
 * /api/diff:
 *   post:
 *     tags: [Diff]
 *     summary: Compare two code snippets
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - oldCode
 *               - newCode
 *             properties:
 *               oldCode:
 *                 type: string
 *               newCode:
 *                 type: string
 *     responses:
 *       200:
 *         description: Difference comparison successful
 *       500:
 *         description: Server error
 */

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