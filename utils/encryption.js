const crypto = require('crypto');
const secret = process.env.ENCRYPTION_KEY; // Use encryption key from environment variables

const encrypt = (text) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secret, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

const decrypt = (encryptedText) => {
  // Handle empty or null content
  if (!encryptedText) {
    return '';
  }

  const parts = encryptedText.split(':');
  
  // Check if we have the correct number of parts
  if (parts.length !== 2 || parts[0] === '' || parts[1] === '') {
    console.log('Invalid encrypted text:', encryptedText); // For debugging
    return ''; // Or handle the error as needed
  }

  const iv = Buffer.from(parts.shift(), 'hex');
  
  // Ensure the IV is of the correct length (16 bytes for AES-256-CBC)
  if (iv.length !== 16) {
    throw new Error('Invalid initialization vector length');
  }

  const encryptedTextBuffer = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secret, 'hex'), iv);
  let decrypted = decipher.update(encryptedTextBuffer, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

module.exports = { encrypt, decrypt };
