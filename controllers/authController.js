const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('../config/database');
const emailService = require('../services/emailService');

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const otpStore = new Map(); // In-memory store for OTPs. In production, use a database.

function getStoredOTP(email) {
    const storedData = otpStore.get(email);
    if (!storedData) return null;
    if (Date.now() - storedData.timestamp > 600000) { // 10 minutes expiry
      otpStore.delete(email);
      return null;
    }
    return storedData.otp;
  }
  
  function clearStoredOTP(email) {
    otpStore.delete(email);
  }
  

  exports.sendOTP = async (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email, { otp, timestamp: Date.now() });
    
    try {
      await emailService.sendOTP(email, otp);
      res.json({ message: 'OTP sent successfully' });
    } catch (error) {
      console.error('Error sending OTP:', error);
      res.status(500).json({ message: 'Failed to send OTP' });
    }
  };

  exports.verifyOTP = async (req, res) => {
    const { email, otp } = req.body;
    console.log('Received verification request:', { email, otp });
  
    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required' });
    }
  
    try {
      const storedOTP = await getStoredOTP(email); // Implement this function to retrieve the stored OTP
      console.log('Stored OTP:', storedOTP);
  
      if (!storedOTP) {
        return res.status(400).json({ message: 'No OTP found for this email' });
      }
  
      if (otp !== storedOTP) {
        return res.status(400).json({ message: 'Invalid OTP' });
      }
  
      // OTP is valid
      await clearStoredOTP(email); // Implement this function to clear the used OTP
      res.json({ message: 'OTP verified successfully' });
    } catch (error) {
      console.error('Error verifying OTP:', error);
      res.status(500).json({ message: 'Server error while verifying OTP' });
    }
  };
  exports.login = async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Find the user by email
      const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      
      if (users.length === 0) {
        return res.status(401).json({ message: 'Invalid email or password' });
      }
  
      const user = users[0];
  
      // Compare the provided password with the stored hash
      const isPasswordValid = await bcrypt.compare(password, user.password);
  
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid email or password' });
      }
  
      // Generate a JWT token
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
      res.json({ token, userId: user.id });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'An error occurred during login' });
    }
  };
exports.register = async (req, res) => {
  console.log('Received registration request:', req.body);
  try {
    const { username, email, password } = req.body;

    // Check if email already exists
    const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email already exists',
      });
    }

    // Check if username already exists
    const [existingUsername] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUsername.length > 0) {
      return res.status(400).json({
        status: 'fail', 
        message: 'Username already exists',
      });
    }

    // Validate password strength
    if (password.length < 8) {
      return res.status(400).json({
        status: 'fail',
        message: 'Password must be at least 8 characters long',
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Insert the new user into the database
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword]
    );

    const token = signToken(result.insertId);

    res.status(201).json({
      status: 'success',
      token,
      data: {
        user: { id: result.insertId, username, email },
      },
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(400).json({
      status: 'fail',
      message: err.message,
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password',
      });
    }

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (users.length === 0 || !(await bcrypt.compare(password, users[0].password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password',
      });
    }

    const token = signToken(users[0].id);
    res.status(200).json({
      status: 'success',
      token,
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message,
    });
  }
};
exports.resetPassword = async (req, res) => {
    const { email, newPassword } = req.body;
  
    try {
      // Find the user by email
      const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      
      if (users.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
  
      // Update the user's password in the database
      await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
  
      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error('Error resetting password:', error);
      res.status(500).json({ message: 'An error occurred while resetting the password' });
    }
  };
exports.checkUsername = async (req, res) => {
  try {
    const { username } = req.params;

    // Validate username format
    if (!username || username.length < 3) {
      return res.status(400).json({
        status: 'fail',
        message: 'Username must be at least 3 characters long',
      });
    }

    // Check if username contains only allowed characters
    const validUsernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!validUsernameRegex.test(username)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Username can only contain letters, numbers, underscores and hyphens',
      });
    }

    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    
    res.json({
      status: 'success',
      available: users.length === 0,
      message: users.length === 0 ? 'Username is available' : 'Username is already taken'
    });
  } catch (err) {
    console.error('Username check error:', err);
    res.status(500).json({
      status: 'error',
      message: 'An error occurred while checking username availability',
    });
  }
};
exports.checkEmail = async (req, res) => {
    try {
      const { email } = req.params;
      const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      
      res.json({ available: users.length === 0 });
    } catch (err) {
      console.error('Email check error:', err);
      res.status(500).json({
        status: 'error',
        message: 'An error occurred while checking email availability',
      });
    }
  };
  exports.changePassword = async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id; // Assuming your authMiddleware adds user info to the request
  
    try {
      // Fetch the user from the database
      const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
      
      if (users.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const user = users[0];
  
      // Verify current password
      const isPasswordCorrect = await bcrypt.compare(currentPassword, user.password);
      if (!isPasswordCorrect) {
        return res.status(400).json({ message: 'Current password is incorrect' });
      }
  
      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 12);
  
      // Update the password in the database
      await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
  
      res.json({ message: 'Password changed successfully' });
    } catch (error) {
      console.error('Error changing password:', error);
      res.status(500).json({ message: 'An error occurred while changing the password' });
    }
  };