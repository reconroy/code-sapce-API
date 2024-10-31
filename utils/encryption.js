const crypto = require('crypto');
require('dotenv').config();

// Convert the key to exactly 32 bytes
function getKey() {
    // Get the key from environment variable
    const originalKey = process.env.ENCRYPTION_KEY || '';
    
    // Create a buffer of 32 bytes
    const buffer = Buffer.alloc(32);
    
    // Copy the original key into the buffer, padded or truncated to 32 bytes
    Buffer.from(originalKey).copy(buffer);
    
    return buffer;
}

const ENCRYPTION_KEY = getKey();
const IV_LENGTH = 16;

function encrypt(text) {
    try {
        // If text is empty or null, return empty string
        if (!text) return '';
        
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let encrypted = cipher.update(text.toString());
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (error) {
        console.error('Encryption error:', error);
        return ''; // Return empty string on error
    }
}

function decrypt(text) {
    try {
        // If text is empty or doesn't contain the separator, return empty string
        if (!text || !text.includes(':')) return '';
        
        const textParts = text.split(':');
        if (textParts.length !== 2) return '';
        
        const iv = Buffer.from(textParts[0], 'hex');
        if (iv.length !== IV_LENGTH) return '';
        
        const encryptedText = Buffer.from(textParts[1], 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        console.error('Decryption error:', error);
        return ''; // Return empty string on error
    }
}

// Export a function to validate the key
function validateKey() {
    return ENCRYPTION_KEY.length === 32;
}

module.exports = { encrypt, decrypt, validateKey };
