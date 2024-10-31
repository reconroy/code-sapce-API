-- Drop database if exists and create new one
DROP DATABASE IF EXISTS codespaces;
CREATE DATABASE codespaces;
USE codespaces;

-- Create users table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    default_codespace_slug VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create codespaces table
CREATE TABLE codespaces (
    id INT PRIMARY KEY AUTO_INCREMENT,
    slug VARCHAR(255) NOT NULL UNIQUE,
    owner_id INT,
    content LONGTEXT ,
    language VARCHAR(50) DEFAULT 'javascript',
    is_public BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,
    access_type ENUM('public', 'private') DEFAULT 'public',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create codespace_access table
CREATE TABLE codespace_access (
    id INT PRIMARY KEY AUTO_INCREMENT,
    codespace_id INT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (codespace_id) REFERENCES codespaces(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_access (codespace_id, user_id)
);

-- Create token_blacklist table
CREATE TABLE token_blacklist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_codespaces_slug ON codespaces(slug);
CREATE INDEX idx_codespaces_owner ON codespaces(owner_id);
CREATE INDEX idx_token_blacklist_expires ON token_blacklist(expires_at);

-- Create event scheduler for cleanup (optional)
SET GLOBAL event_scheduler = ON;

DELIMITER //
CREATE EVENT cleanup_expired_tokens
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    DELETE FROM token_blacklist WHERE expires_at < NOW();
END//
DELIMITER ;