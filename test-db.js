const { Pool } = require('pg');
const fs = require('fs');
const dotenv = require('dotenv');

// Read and parse .env file
const envContent = fs.readFileSync('.env', 'utf8');
const envLines = envContent.split('\n');
const envVars = {};

envLines.forEach((line) => {
  const [key, value] = line.split('=');
  if (key && value) {
    envVars[key.trim()] = value.trim();
  }
});

// Create a connection pool
const pool = new Pool({
  host: envVars.DB_HOST || 'localhost',
  port: parseInt(envVars.DB_PORT) || 5432,
  user: envVars.DB_USERNAME || 'postgres',
  password: envVars.DB_PASSWORD,
  database: envVars.DB_DATABASE || 'nestjs-auth',
});

// Test the connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Error connecting to the database:');
    console.error(err);
  } else {
    console.log('Successfully connected to PostgreSQL!');
    console.log('Current time from database:', res.rows[0].now);
  }

  // Close the connection
  pool.end();
});
