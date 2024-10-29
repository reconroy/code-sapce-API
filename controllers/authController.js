const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const pool = require("../config/database");
const emailService = require("../services/emailService");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const otpStore = new Map(); // In-memory store for OTPs. In production, use a database.

function getStoredOTP(email) {
  const storedData = otpStore.get(email);
  if (!storedData) return null;
  if (Date.now() - storedData.timestamp > 600000) {
    // 10 minutes expiry
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
    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("Error sending OTP:", error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
};

exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;
  console.log("Received verification request:", { email, otp });

  if (!email || !otp) {
    return res.status(400).json({ message: "Email and OTP are required" });
  }

  try {
    const storedOTP = await getStoredOTP(email); // Implement this function to retrieve the stored OTP
    console.log("Stored OTP:", storedOTP);

    if (!storedOTP) {
      return res.status(400).json({ message: "No OTP found for this email" });
    }

    if (otp !== storedOTP) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // OTP is valid
    await clearStoredOTP(email); // Implement this function to clear the used OTP
    res.json({ message: "OTP verified successfully" });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ message: "Server error while verifying OTP" });
  }
};
exports.login = async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
      return res.status(400).json({
        status: "fail",
        message: "Please provide email/username and password",
      });
    }

    // Check if the input is an email or username
    const isEmail = emailOrUsername.includes("@");
    const query = isEmail
      ? "SELECT * FROM users WHERE email = ?"
      : "SELECT * FROM users WHERE username = ?";

    const [users] = await pool.query(query, [emailOrUsername]);

    if (
      users.length === 0 ||
      !(await bcrypt.compare(password, users[0].password))
    ) {
      return res.status(401).json({
        status: "fail",
        message: "Incorrect email/username or password",
      });
    }

    const token = signToken(users[0].id);
    res.status(200).json({
      status: "success",
      token,
    });
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};
exports.register = async (req, res) => {
  const connection = await pool.getConnection();
  await connection.beginTransaction();
  
  try {
    const { username, email, password } = req.body;

    // Input validation
    if (!username || !email || !password) {
      return res.status(400).json({
        status: "fail",
        message: "Please provide username, email, and password",
      });
    }

    // Validate username format
    if (username.length < 3) {
      return res.status(400).json({
        status: "fail",
        message: "Username must be at least 3 characters long",
      });
    }

    const validUsernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!validUsernameRegex.test(username)) {
      return res.status(400).json({
        status: "fail",
        message:
          "Username can only contain letters, numbers, underscores and hyphens",
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        status: "fail",
        message: "Please provide a valid email address",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const [userResult] = await connection.query(
      "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );

    // Create default codespace
    const defaultContent = `// Welcome to your private CodeSpace, ${username}! 🚀\n// This is your personal workspace where you can:\n// - Write and test code\n// - Save your snippets\n// - Work on your projects\n\nfunction greeting() {\n  console.log("Welcome to CodeSpace!");\n  console.log("This is your private workspace.");\n  console.log("Happy coding! 🎉");\n}\n\n// Let's start coding!\ngreeting();`;

    await connection.query(
      `INSERT INTO codespaces (
        slug, 
        owner_id, 
        content, 
        language, 
        is_public, 
        is_default, 
        access_type
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        username,
        userResult.insertId,
        defaultContent,
        'javascript',
        false,
        true,
        'private'
      ]
    );

    await connection.commit();

    const token = signToken(userResult.insertId);

    // Send success response with all necessary data
    res.status(201).json({
      status: "success",
      token,
      data: {
        user: {
          id: userResult.insertId,
          username,
          email,
          default_codespace: username
        }
      }
    });

  } catch (err) {
    await connection.rollback();
    console.error("Registration error:", err);
    throw new Error("Registration failed. Please try again.");
  } finally {
    connection.release();
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    // Validate input
    if (!email || !newPassword) {
      return res.status(400).json({
        status: 'error',
        message: 'Email and new password are required'
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update the password in database
    const [result] = await pool.query(
      'UPDATE users SET password = ? WHERE email = ?',
      [hashedPassword, email]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Password reset successful'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to reset password'
    });
  }
};
exports.checkUsername = async (req, res) => {
  try {
    const { username } = req.params;

    // First check if username exists in users table
    const [users] = await pool.query(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (users.length > 0) {
      return res.json({
        available: false,
        message: 'Username is already taken'
      });
    }

    // Then check if username exists as a codespace slug
    const [codespaces] = await pool.query(
      'SELECT id FROM codespaces WHERE slug = ?',
      [username]
    );

    if (codespaces.length > 0) {
      return res.json({
        available: false,
        message: 'This username conflicts with an existing codespace'
      });
    }

    // If neither exists, username is available
    res.json({
      available: true,
      message: 'Username is available'
    });

  } catch (error) {
    console.error('Username check error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to check username availability'
    });
  }
};
exports.checkEmail = async (req, res) => {
  try {
    const { email } = req.params;
    const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    res.json({ available: users.length === 0 });
  } catch (err) {
    console.error("Email check error:", err);
    res.status(500).json({
      status: "error",
      message: "An error occurred while checking email availability",
    });
  }
};
exports.changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id; // Assuming your authMiddleware adds user info to the request

  try {
    // Fetch the user from the database
    const [users] = await pool.query("SELECT * FROM users WHERE id = ?", [
      userId,
    ]);

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];

    // Verify current password
    const isPasswordCorrect = await bcrypt.compare(
      currentPassword,
      user.password
    );
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update the password in the database
    await pool.query("UPDATE users SET password = ? WHERE id = ?", [
      hashedPassword,
      userId,
    ]);

    res.json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Error changing password:", error);
    res
      .status(500)
      .json({ message: "An error occurred while changing the password" });
  }
};
// Add this to your verifyToken function to check blacklist

exports.logout = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    console.log("Auth header:", authHeader); // Debug log

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      console.log("No valid auth header found"); // Debug log
      return res.status(401).json({
        status: "fail",
        message: "No token provided",
      });
    }

    const token = authHeader.split(" ")[1];
    console.log("Token to blacklist:", token); // Debug log

    try {
      // Add current timestamp log
      console.log("Current timestamp:", new Date());

      const [result] = await pool.query(
        "INSERT INTO token_blacklist (token, expires_at) VALUES (?, ?)",
        [token, new Date(Date.now() + 24 * 60 * 60 * 1000)]
      );

      console.log("Database insert result:", result); // Debug log

      if (result.affectedRows > 0) {
        // Query to verify the insertion
        const [verification] = await pool.query(
          "SELECT * FROM token_blacklist WHERE token = ?",
          [token]
        );
        console.log("Verification query result:", verification);

        res.status(200).json({
          status: "success",
          message: "Logged out successfully",
        });
      } else {
        throw new Error("Failed to insert token into blacklist");
      }
    } catch (dbError) {
      console.error("Database error details:", dbError);
      throw new Error(`Failed to blacklist token: ${dbError.message}`);
    }
  } catch (error) {
    console.error("Full logout error:", error);
    res.status(500).json({
      status: "error",
      message: "An error occurred during logout",
      details:
        process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

exports.verifyToken = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.json({ valid: false });
    }

    const token = authHeader.split(" ")[1];

    // Check if token is blacklisted
    const [blacklistedTokens] = await pool.query(
      "SELECT * FROM token_blacklist WHERE token = ? AND expires_at > NOW()",
      [token]
    );

    if (blacklistedTokens.length > 0) {
      return res.json({ valid: false });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if user still exists
    const [users] = await pool.query("SELECT id FROM users WHERE id = ?", [
      decoded.id,
    ]);

    if (users.length === 0) {
      return res.json({ valid: false });
    }

    res.json({ valid: true });
  } catch (error) {
    console.error("Token verification error:", error);
    res.json({ valid: false });
  }
};
// Add this new endpoint to check if email exists
exports.checkEmailExists = async (req, res) => {
  try {
    const { email } = req.params;
    const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    res.json({ exists: users.length > 0 });
  } catch (err) {
    console.error("Email check error:", err);
    res.status(500).json({
      status: "error",
      message: "An error occurred while checking email",
    });
  }
};