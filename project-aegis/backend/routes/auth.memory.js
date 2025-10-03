const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

// In-memory user store (demo only)
// Structure: username -> { username, passwordHash, email, role, mfaEnabled, createdAt }
const bcrypt = require('bcrypt');
const users = new Map();

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'replace-me-with-secure-random-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRE || '15m';

function createToken(user) {
  const payload = { sub: user.username, role: user.role };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

router.post(
  '/register',
  [
    body('username').isString().trim().isLength({ min: 3, max: 50 }).escape(),
    body('password').isString().isLength({ min: 8 }),
    body('email').optional().isEmail().normalizeEmail(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password, email } = req.body;
    if (users.has(username)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = { username, passwordHash, email: email || null, role: 'citizen', mfaEnabled: false, createdAt: new Date().toISOString() };
    users.set(username, user);
    return res.status(201).json({ success: true, message: 'User registered' });
  }
);

router.post(
  '/login',
  [
    body('username').isString().notEmpty(),
    body('password').isString().notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;
    const user = users.get(username);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = createToken(user);
    return res.json({ success: true, token, expiresIn: JWT_EXPIRES_IN, user: { username: user.username, role: user.role, createdAt: user.createdAt } });
  }
);

router.get('/me', (req, res) => {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.get(payload.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ user: { username: user.username, role: user.role, createdAt: user.createdAt } });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

module.exports = router;


