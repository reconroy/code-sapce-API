const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const authMiddleware = require('../middleware/authMiddleware');
const codespaceController = require('../controllers/codespaceController');

/**
 * @swagger
 * tags:
 *   name: Codespace
 *   description: Codespace management endpoints
 * 
 * /api/codespace/{slug}:
 *   get:
 *     tags: [Codespace]
 *     summary: Get a codespace by slug with access control
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Codespace found successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     slug:
 *                       type: string
 *                     content:
 *                       type: string
 *                     language:
 *                       type: string
 *                     owner_username:
 *                       type: string
 *                     access_type:
 *                       type: string
 *                       enum: [public, private, shared]
 *                     hasAccess:
 *                       type: boolean
 *       401:
 *         description: Authentication required for shared codespace
 *       403:
 *         description: Access denied or passkey required
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: fail
 *                 message:
 *                   type: string
 *                 requiresPasskey:
 *                   type: boolean
 *                 owner:
 *                   type: string
 *   put:
 *     tags: [Codespace]
 *     summary: Update a codespace
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               content:
 *                 type: string
 *               language:
 *                 type: string
 *     responses:
 *       200:
 *         description: Codespace updated
 *   delete:
 *     tags: [Codespace]
 *     summary: Delete a codespace
 *     description: Delete a codespace by its slug. Only the owner can delete their codespace.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema:
 *           type: string
 *         description: The slug of the codespace to delete
 *     responses:
 *       200:
 *         description: Codespace deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 message:
 *                   type: string
 *                   example: Codespace deleted successfully
 *       401:
 *         description: Unauthorized - User not authenticated
 *       403:
 *         description: Forbidden - User does not have permission to delete this codespace
 *       404:
 *         description: Codespace not found
 *       500:
 *         description: Server error
 * 
 * /api/codespace/{slug}/settings:
 *   put:
 *     tags: [Codespace]
 *     summary: Update codespace settings
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newSlug:
 *                 type: string
 *               accessType:
 *                 type: string
 *                 enum: [public, private, shared]
 *               passkey:
 *                 type: string
 *               isArchived:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Settings updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     newSlug:
 *                       type: string
 *                     accessType:
 *                       type: string
 *                     isArchived:
 *                       type: boolean
 *                     hasPasskey:
 *                       type: boolean
 *       403:
 *         description: Permission denied
 *       404:
 *         description: Codespace not found
 * 
 * /api/codespace/{slug}/access-logs:
 *   get:
 *     tags: [Codespace]
 *     summary: Get codespace access logs
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Access logs retrieved successfully
 * 
 * /api/codespace:
 *   post:
 *     tags: [Codespace]
 *     summary: Create a new codespace
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - slug
 *             properties:
 *               slug:
 *                 type: string
 *               content:
 *                 type: string
 *               language:
 *                 type: string
 *                 default: javascript
 *     responses:
 *       200:
 *         description: Codespace created or existing one returned
 *       500:
 *         description: Server error
 * 
 * /api/codespace/check-slug/{slug}:
 *   get:
 *     tags: [Codespace]
 *     summary: Check if a slug is available
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Slug availability status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 available:
 *                   type: boolean
 * 
 * /api/codespace/user/list:
 *   get:
 *     tags: [Codespace]
 *     summary: Get all codespaces for the authenticated user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of user's codespaces
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                       slug:
 *                         type: string
 *                       owner_username:
 *                         type: string
 *                       content:
 *                         type: string
 *                       language:
 *                         type: string
 *                       is_default:
 *                         type: boolean
 */

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

// Add this new route for access logs
router.get('/:slug/access-logs', authMiddleware, codespaceController.getAccessLogs);

module.exports = router;