const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

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
