/**
 * Script to initialize an admin user with a hashed password
 * Usage: node db/init-admin.js <username> <password>
 *
 * Example:
 * node db/init-admin.js admin mysecurepassword123
 */

const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initializeAdmin(username, password) {
  if (!username || !password) {
    console.error('Usage: node db/init-admin.js <username> <password>');
    process.exit(1);
  }

  try {
    // Hash the password with a salt rounds of 10
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert or update the admin user
    const result = await pool.query(
      `INSERT INTO admin_users (username, password_hash, email, created_at, updated_at)
       VALUES ($1, $2, $3, NOW(), NOW())
       ON CONFLICT (username) DO UPDATE
       SET password_hash = EXCLUDED.password_hash, updated_at = NOW()
       RETURNING id, username, email, created_at`,
      [username, passwordHash, null]
    );

    console.log('✅ Admin user initialized successfully');
    console.log(`   Username: ${result.rows[0].username}`);
    console.log(`   Created: ${result.rows[0].created_at}`);

    process.exit(0);
  } catch (err) {
    console.error('❌ Error initializing admin user:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

const args = process.argv.slice(2);
initializeAdmin(args[0], args[1]);
