-- Create the database
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
    content TEXT,
    language VARCHAR(50) DEFAULT 'javascript',
    is_public BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,
    access_type ENUM('public', 'private') DEFAULT 'public',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Create codespace_access table (for managing private codespace access)
CREATE TABLE codespace_access (
    id INT PRIMARY KEY AUTO_INCREMENT,
    codespace_id INT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (codespace_id) REFERENCES codespaces(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY unique_access (codespace_id, user_id)
);

-- Create token_blacklist table (for logout functionality)
CREATE TABLE token_blacklist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_codespaces_slug ON codespaces(slug);
CREATE INDEX idx_codespaces_owner ON codespaces(owner_id);
CREATE INDEX idx_token_blacklist_expires ON token_blacklist(expires_at);