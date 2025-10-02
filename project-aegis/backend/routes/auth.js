const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const User = require('../models/User');
const AuthMiddleware = require('../middleware/auth');
const SecurityConfig = require('../config/security');
const encryptionService = require('../utils/encryption');

const router = express.Router();

// Apply strict rate limiting to auth routes
router.use(SecurityConfig.getAuthRateLimiter());

// Input validation rules
const registerValidation = [
  body('username')
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-50 characters and contain only letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be at least 8 characters with uppercase, lowercase, number, and special character'),
  body('governmentId')
    .isLength({ min: 10, max: 20 })
    .matches(/^[a-zA-Z0-9]+$/)
    .withMessage('Government ID must be 10-20 alphanumeric characters'),
  body('governmentIdType')
    .isIn(['aadhaar', 'pan', 'passport', 'voter_id', 'driving_license'])
    .withMessage('Invalid government ID type'),
  body('firstName')
    .isLength({ min: 1, max: 50 })
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('First name must contain only letters and spaces'),
  body('lastName')
    .isLength({ min: 1, max: 50 })
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Last name must contain only letters and spaces'),
  body('phoneNumber')
    .matches(/^[6-9]\d{9}$/)
    .withMessage('Please provide a valid Indian phone number')
];

const loginValidation = [
  body('username')
    .notEmpty()
    .withMessage('Username or email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  body('mfaToken')
    .optional()
    .isLength({ min: 6, max: 6 })
    .isNumeric()
    .withMessage('MFA token must be 6 digits')
];

// Utility function to generate JWT tokens
const generateTokens = (userId) => {
  const payload = { userId, iat: Math.floor(Date.now() / 1000) };
  
  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE || '15m'
  });
  
  const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d'
  });
  
  return { accessToken, refreshToken };
};

// POST /api/auth/register - User registration
router.post('/register', registerValidation, async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }
    
    const {
      username,
      email,
      password,
      governmentId,
      governmentIdType,
      firstName,
      lastName,
      phoneNumber
    } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [
        { username },
        { email },
        { governmentId: encryptionService.encryptForDatabase(governmentId) }
      ]
    });
    
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User already exists with this username, email, or government ID',
        code: 'USER_EXISTS'
      });
    }
    
    // Create new user
    const user = new User({
      username,
      email,
      password, // Will be hashed by pre-save middleware
      governmentId: encryptionService.encryptForDatabase(governmentId),
      governmentIdType,
      personalInfo: {
        firstName: encryptionService.encryptForDatabase(firstName),
        lastName: encryptionService.encryptForDatabase(lastName),
        phoneNumber: encryptionService.encryptForDatabase(phoneNumber)
      },
      role: 'citizen',
      permissions: [
        { resource: 'profile', actions: ['read', 'update'] },
        { resource: 'documents', actions: ['read', 'create'] }
      ]
    });
    
    // Add registration audit log
    user.addAuditLog(
      'user_registration',
      req.ip,
      req.get('User-Agent'),
      { registrationMethod: 'standard' }
    );
    
    await user.save();
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user._id);
    
    // Store refresh token
    user.refreshTokens.push({
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      device: req.get('User-Agent'),
      ipAddress: req.ip
    });
    
    await user.save();
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: user.toJSON(),
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: process.env.JWT_EXPIRE || '15m'
        }
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during registration',
      code: 'REGISTRATION_ERROR'
    });
  }
});

// POST /api/auth/login - User login
router.post('/login', loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }
    
    const { username, password, mfaToken } = req.body;
    
    // Find and verify user credentials
    const user = await User.findByCredentials(username, password);
    
    // Check MFA if enabled
    if (user.mfa.enabled) {
      if (!mfaToken) {
        return res.status(200).json({
          success: false,
          message: 'MFA token required',
          code: 'MFA_REQUIRED',
          mfaRequired: true
        });
      }
      
      const isMFAValid = user.verifyMFAToken(mfaToken);
      if (!isMFAValid) {
        // Try backup code
        const isBackupCodeValid = user.useMFABackupCode(mfaToken);
        if (!isBackupCodeValid) {
          await user.handleFailedLogin();
          return res.status(401).json({
            success: false,
            message: 'Invalid MFA token',
            code: 'INVALID_MFA_TOKEN'
          });
        }
        await user.save(); // Save backup code usage
      }
      
      user.mfa.lastUsed = new Date();
    }
    
    // Handle successful login
    await user.handleSuccessfulLogin(req.ip, req.get('User-Agent'));
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user._id);
    
    // Store refresh token
    user.refreshTokens.push({
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      device: req.get('User-Agent'),
      ipAddress: req.ip
    });
    
    // Clean up old refresh tokens (keep only last 5)
    if (user.refreshTokens.length > 5) {
      user.refreshTokens = user.refreshTokens.slice(-5);
    }
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.toJSON(),
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: process.env.JWT_EXPIRE || '15m'
        }
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    
    if (error.message.includes('Invalid credentials') || 
        error.message.includes('Account is temporarily locked')) {
      return res.status(401).json({
        success: false,
        message: error.message,
        code: 'INVALID_CREDENTIALS'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Internal server error during login',
      code: 'LOGIN_ERROR'
    });
  }
});

// POST /api/auth/refresh - Refresh access token
router.post('/refresh', AuthMiddleware.verifyRefreshToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const user = await User.findById(req.user.userId);
    
    // Generate new tokens
    const tokens = generateTokens(user._id);
    
    // Remove old refresh token and add new one
    user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
    user.refreshTokens.push({
      token: tokens.refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      device: req.get('User-Agent'),
      ipAddress: req.ip
    });
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        tokens: {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresIn: process.env.JWT_EXPIRE || '15m'
        }
      }
    });
    
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during token refresh',
      code: 'REFRESH_ERROR'
    });
  }
});

// POST /api/auth/logout - Logout user
router.post('/logout', AuthMiddleware.verifyToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const user = await User.findById(req.user.userId);
    
    if (refreshToken) {
      // Remove specific refresh token
      user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
    } else {
      // Remove all refresh tokens (logout from all devices)
      user.refreshTokens = [];
    }
    
    user.addAuditLog('user_logout', req.ip, req.get('User-Agent'));
    await user.save();
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during logout',
      code: 'LOGOUT_ERROR'
    });
  }
});

// GET /api/auth/mfa/setup - Setup MFA
router.get('/mfa/setup', AuthMiddleware.verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (user.mfa.enabled) {
      return res.status(400).json({
        success: false,
        message: 'MFA is already enabled',
        code: 'MFA_ALREADY_ENABLED'
      });
    }
    
    // Generate MFA secret
    const secret = user.generateMFASecret();
    await user.save();
    
    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    
    res.json({
      success: true,
      message: 'MFA setup initiated',
      data: {
        secret: secret.base32,
        qrCode: qrCodeUrl,
        manualEntryKey: secret.base32
      }
    });
    
  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during MFA setup',
      code: 'MFA_SETUP_ERROR'
    });
  }
});

// POST /api/auth/mfa/verify - Verify and enable MFA
router.post('/mfa/verify', 
  AuthMiddleware.verifyToken,
  [body('token').isLength({ min: 6, max: 6 }).isNumeric()],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Invalid MFA token format',
          errors: errors.array()
        });
      }
      
      const { token } = req.body;
      const user = await User.findById(req.user.userId);
      
      if (user.mfa.enabled) {
        return res.status(400).json({
          success: false,
          message: 'MFA is already enabled',
          code: 'MFA_ALREADY_ENABLED'
        });
      }
      
      // Verify token
      const isValid = user.verifyMFAToken(token);
      if (!isValid) {
        return res.status(400).json({
          success: false,
          message: 'Invalid MFA token',
          code: 'INVALID_MFA_TOKEN'
        });
      }
      
      // Enable MFA and generate backup codes
      user.mfa.enabled = true;
      const backupCodes = user.generateMFABackupCodes();
      
      user.addAuditLog('mfa_enabled', req.ip, req.get('User-Agent'));
      await user.save();
      
      res.json({
        success: true,
        message: 'MFA enabled successfully',
        data: {
          backupCodes,
          message: 'Please save these backup codes in a secure location'
        }
      });
      
    } catch (error) {
      console.error('MFA verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during MFA verification',
        code: 'MFA_VERIFY_ERROR'
      });
    }
  }
);

// POST /api/auth/mfa/disable - Disable MFA
router.post('/mfa/disable', 
  AuthMiddleware.verifyToken,
  [body('password').notEmpty(), body('token').isLength({ min: 6, max: 6 }).isNumeric()],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }
      
      const { password, token } = req.body;
      const user = await User.findById(req.user.userId).select('+password');
      
      // Verify password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          message: 'Invalid password',
          code: 'INVALID_PASSWORD'
        });
      }
      
      // Verify MFA token
      const isTokenValid = user.verifyMFAToken(token);
      if (!isTokenValid) {
        return res.status(400).json({
          success: false,
          message: 'Invalid MFA token',
          code: 'INVALID_MFA_TOKEN'
        });
      }
      
      // Disable MFA
      user.mfa.enabled = false;
      user.mfa.secret = undefined;
      user.mfa.backupCodes = [];
      
      user.addAuditLog('mfa_disabled', req.ip, req.get('User-Agent'));
      await user.save();
      
      res.json({
        success: true,
        message: 'MFA disabled successfully'
      });
      
    } catch (error) {
      console.error('MFA disable error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during MFA disable',
        code: 'MFA_DISABLE_ERROR'
      });
    }
  }
);

// GET /api/auth/me - Get current user profile
router.get('/me', AuthMiddleware.verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }
    
    res.json({
      success: true,
      data: { user: user.toJSON() }
    });
    
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'PROFILE_ERROR'
    });
  }
});

module.exports = router;
