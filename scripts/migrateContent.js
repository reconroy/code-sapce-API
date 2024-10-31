// migrateContent if content is not encrypted 
const pool = require('../config/database');
const { encrypt } = require('../utils/encryption');

async function migrateContent() {
  try {
    // Get all codespaces
    const [codespaces] = await pool.query('SELECT id, content FROM codespaces');
    
    for (const codespace of codespaces) {
      // Skip if content is already encrypted (contains ':')
      if (!codespace.content || codespace.content.includes(':')) {
        continue;
      }
      
      // Encrypt the content
      const encryptedContent = encrypt(codespace.content);
      
      // Update the database
      await pool.query(
        'UPDATE codespaces SET content = ? WHERE id = ?',
        [encryptedContent, codespace.id]
      );
      
      console.log(`Migrated content for codespace ${codespace.id}`);
    }
    
    console.log('Migration completed successfully');
  } catch (error) {
    console.error('Migration failed:', error);
  } finally {
    pool.end();
  }
}

migrateContent();
