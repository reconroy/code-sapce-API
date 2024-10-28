const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// 1. User Registration
router.post('/register', authController.register);
// When frontend makes POST request to /api/auth/register
// Used for creating new user accounts

// 2. User Login
router.post('/login', authController.login);
// When frontend makes POST request to /api/auth/login
// Used for authenticating existing users

// 3. Token Verification
router.get('/verify', authController.verifyToken);
// When frontend makes GET request to /api/auth/verify
// Used to check if user's token is still valid

module.exports = router;