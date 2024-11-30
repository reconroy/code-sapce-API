const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication endpoints
 * 
 * /api/auth/login:
 *   post:
 *     tags: [Auth]
 *     summary: Login user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - emailOrUsername
 *               - password
 *             properties:
 *               emailOrUsername:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 * 
 * /api/auth/register:
 *   post:
 *     tags: [Auth]
 *     summary: Register new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Registration successful
 * 
 * /api/auth/check-username/{username}:
 *   get:
 *     tags: [Auth]
 *     summary: Check username availability
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Username availability status
 * 
 * /api/auth/check-email/{email}:
 *   get:
 *     tags: [Auth]
 *     summary: Check email availability
 *     parameters:
 *       - in: path
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Email availability status
 * 
 * /api/auth/send-otp:
 *   post:
 *     tags: [Auth]
 *     summary: Send OTP for password reset
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP sent successfully
 * 
 * /api/auth/verify-otp:
 *   post:
 *     tags: [Auth]
 *     summary: Verify OTP
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - otp
 *             properties:
 *               email:
 *                 type: string
 *               otp:
 *                 type: string
 *     responses:
 *       200:
 *         description: OTP verified successfully
 * 
 * /api/auth/reset-password:
 *   post:
 *     tags: [Auth]
 *     summary: Reset password
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - newPassword
 *             properties:
 *               email:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password reset successful
 * 
 * /api/auth/change-password:
 *   post:
 *     tags: [Auth]
 *     summary: Change user password
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       401:
 *         description: Current password is incorrect
 * 
 * /api/auth/default-codespace:
 *   get:
 *     tags: [Auth]
 *     summary: Get or create user's default codespace
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Default codespace information
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 defaultCodespace:
 *                   type: string
 *                 username:
 *                   type: string
 *       404:
 *         description: User not found
 * 
 * /api/auth/user/default-codespace:
 *   get:
 *     tags: [Auth]
 *     summary: Get or create user's default codespace
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Default codespace information
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 defaultCodespace:
 *                   type: string
 *                 username:
 *                   type: string
 *       404:
 *         description: User not found
 */

// Authentication routes
router.post('/login', authController.login);
router.post('/register', authController.register);
router.post('/logout', authController.logout);
router.get('/verify', authController.verifyToken);

// Session management route
router.post('/extend-session', authMiddleware, authController.extendSession);

// Email and username verification routes
router.get('/check-username/:username', authController.checkUsername);
router.get('/check-email/:email', authController.checkEmailExists);
router.get('/check-email-exists/:email', authController.checkEmailExists);

// OTP routes
router.post('/send-otp', authController.sendOTP);
router.post('/verify-otp', authController.verifyOTP);

// Password management routes
router.post('/reset-password', authController.resetPassword);
router.post('/change-password', authController.changePassword);

// Default codespace route (protected)
router.get('/user/default-codespace', authMiddleware, authController.getDefaultCodespace);

// User count route
router.get('/users/count', authController.getUserCount);

// Add this new route for fetching user data
router.get('/users/me', authMiddleware, authController.getCurrentUser);

module.exports = router;
