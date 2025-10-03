// backend/server.js
require('dotenv').config();

const fs = require('fs');
const https = require('https');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
// Secure auth routes and DB
const authRoutes = require('./routes/auth');
const authRoutesMemory = require('./routes/auth.memory');
const DatabaseManager = require('./config/database');

// -- Simple in-memory user store for demo only (replace with real DB) --
const users = new Map(); // key: username, value: { passwordHash, createdAt }

// -- Environment variables --
const PORT = process.env.PORT || 3001;
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || 'replace-me-with-secure-random-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const HTTPS_ENABLED = process.env.HTTPS_ENABLED === 'true'; // optional
const DISABLE_DB = process.env.DISABLE_DB === 'true';
const HTTPS_KEY = process.env.HTTPS_KEY || '';
const HTTPS_CERT = process.env.HTTPS_CERT || '';

const app = express();

// ------ Middlewares --------
// Security headers
app.use(helmet());

// Logging (avoid logging sensitive values)
app.use(morgan('combined'));

// CORS - restrict origin to frontend
app.use(
  cors({
    origin: CORS_ORIGIN,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  })
);

// JSON parsing
app.use(express.json());

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: { error: 'Too many requests, please try again later.' },
});

// Helper: mask logging of sensitive fields
function maskSensitive(obj = {}, sensitiveFields = ['password']) {
  const copy = { ...obj };
  for (const field of sensitiveFields) {
    if (field in copy) copy[field] = '****';
  }
  return copy;
}

// ----------------- Routes ------------------

// Health
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// Mount secure auth routes only when DB is enabled
app.use('/api/auth', DISABLE_DB ? authRoutesMemory : authRoutes);

/**
 * Register - secure example
 * - Validates input
 * - Hashes password with bcrypt
 * - Stores user in memory (replace with DB)
 */
app.post(
  '/api/register',
  authLimiter,
  [
    body('username').isString().trim().isLength({ min: 3, max: 50 }).escape(),
    body('password').isString().isLength({ min: 8 }).withMessage('Password must be >= 8 chars'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;

    if (users.has(username)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    try {
      const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
      const passwordHash = await bcrypt.hash(password, saltRounds);

      users.set(username, { passwordHash, createdAt: new Date().toISOString() });

      // Never return the hash or password to client
      return res.status(201).json({ success: true, message: 'User registered' });
    } catch (err) {
      console.error('Register error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * Login - secure example
 * - Validates input
 * - Compares password hashes
 * - Issues a signed JWT (short lived)
 * - DOES NOT log plaintext passwords
 */
app.post(
  '/api/login',
  authLimiter,
  [
    body('username').isString().trim().isLength({ min: 3, max: 50 }).escape(),
    body('password').isString().isLength({ min: 8 }),
  ],
  async (req, res) => {
    // Validate request input
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;

    // For logging: mask sensitive fields
    console.log('Login attempt:', maskSensitive({ username, password }));

    const user = users.get(username);
    if (!user) {
      // Generic message to avoid username enumeration
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    try {
      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) return res.status(401).json({ error: 'Invalid credentials' });

      // Issue JWT
      const tokenPayload = { sub: username };
      const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

      // Return token (in production, consider httpOnly secure cookie)
      return res.json({ success: true, token, expiresIn: JWT_EXPIRES_IN });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Example protected route
function authenticateJwt(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing authorization header' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid auth format' });

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.get('/api/profile', authenticateJwt, (req, res) => {
  // Minimal profile response (no secrets)
  const username = req.user.sub;
  return res.json({ username, registeredAt: users.get(username)?.createdAt || null });
});

// Fallback
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ---- Start server (HTTP or optional HTTPS) ----
function startHttpServers() {
    if (HTTPS_ENABLED && HTTPS_KEY && HTTPS_CERT) {
      try {
        const key = fs.readFileSync(path.resolve(HTTPS_KEY));
        const cert = fs.readFileSync(path.resolve(HTTPS_CERT));
        https.createServer({ key, cert }, app).listen(PORT, () => {
          console.log(`🚀 Secure backend (HTTPS) running on https://localhost:${PORT}`);
        });
      } catch (err) {
        console.error('Failed to start HTTPS server:', err);
        process.exit(1);
      }
    } else {
      app.listen(PORT, () => {
        console.log(`🚀 Backend server running on http://localhost:${PORT}`);
        if (process.env.NODE_ENV !== 'production') {
          console.log('⚠️ Running in non-production mode. HTTPS is recommended for real deployments.');
        }
      });
    }
}

if (DISABLE_DB) {
  console.log('⚙️  Starting server with DISABLE_DB=true (no MongoDB connection).');
  startHttpServers();
} else {
  // Start server only after DB connects
  DatabaseManager.connect()
    .then(() => startHttpServers())
    .catch((err) => {
      console.error('❌ Database connection failed. Server not started.', err);
      process.exit(1);
    });
}
