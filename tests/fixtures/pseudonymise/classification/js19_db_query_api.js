const { Pool } = require('pg');

const pool = new Pool();

async function listUsers(limit) {
  const result = await pool.query('SELECT 1 LIMIT $1', [limit]);
  return result.rows;
}
