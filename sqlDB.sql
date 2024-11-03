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
    content LONGTEXT,
    language VARCHAR(50) DEFAULT 'javascript',
    is_public BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,
    is_archived BOOLEAN DEFAULT false,
    passkey VARCHAR(255) DEFAULT NULL,
    access_type ENUM('public', 'private', 'shared') DEFAULT 'public',
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

-- Create cleanup_logs table for tracking deleted guest codespaces
CREATE TABLE cleanup_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    deleted_slug VARCHAR(255) NOT NULL,
    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_codespaces_slug ON codespaces(slug);
CREATE INDEX idx_codespaces_owner ON codespaces(owner_id);
CREATE INDEX idx_codespaces_archived ON codespaces(is_archived);
CREATE INDEX idx_token_blacklist_expires ON token_blacklist(expires_at);
CREATE INDEX idx_cleanup_logs_slug ON cleanup_logs(deleted_slug);

-- Enable Event Scheduler
SET GLOBAL event_scheduler = ON;

-- Drop existing events and triggers
DROP EVENT IF EXISTS cleanup_guest_codespaces;
DROP EVENT IF EXISTS cleanup_expired_tokens;
DROP TRIGGER IF EXISTS log_deleted_codespaces;
DROP TRIGGER IF EXISTS cleanup_logs_maintenance;

-- Create trigger for logging deleted guest codespaces
DELIMITER //
CREATE TRIGGER log_deleted_codespaces
BEFORE DELETE ON codespaces
FOR EACH ROW
BEGIN
    IF OLD.owner_id IS NULL THEN
        INSERT INTO cleanup_logs (deleted_slug) 
        SELECT OLD.slug 
        WHERE NOT EXISTS (
            SELECT 1 FROM cleanup_logs 
            WHERE deleted_slug = OLD.slug
        );
    END IF;
END//
DELIMITER ;

-- Create trigger for cleaning cleanup_logs when codespace is recreated
DELIMITER //
CREATE TRIGGER cleanup_logs_maintenance
AFTER INSERT ON codespaces
FOR EACH ROW
BEGIN
    DELETE FROM cleanup_logs 
    WHERE deleted_slug = NEW.slug;
END//
DELIMITER ;

-- Create event for cleaning up expired tokens
DELIMITER //
CREATE EVENT cleanup_expired_tokens
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    DELETE FROM token_blacklist 
    WHERE expires_at < NOW();
END//
DELIMITER ;

-- Create event for cleaning up guest codespaces
DELIMITER //
CREATE EVENT cleanup_guest_codespaces
ON SCHEDULE EVERY 1 MINUTE
ENABLE
DO
BEGIN
    -- First, log the codespaces that will be deleted
    INSERT INTO cleanup_logs (deleted_slug)
    SELECT slug FROM codespaces 
    WHERE owner_id IS NULL 
    AND updated_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)
    AND slug NOT IN (SELECT deleted_slug FROM cleanup_logs);

    -- Then delete the expired codespaces
    DELETE FROM codespaces 
    WHERE owner_id IS NULL 
    AND updated_at < DATE_SUB(NOW(), INTERVAL 24 HOUR);
END//
DELIMITER ;

-- Verify setup
SHOW EVENTS;
SHOW TRIGGERS;
SELECT @@event_scheduler;