const jwt = require('jsonwebtoken');
const User = require('../models/User');

class AuthMiddleware {
  // Verify JWT token
  static async verifyToken(req, res, next) {
    try {
      const authHeader = req.header('Authorization');
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          message: 'Access denied. No valid token provided.',
          code: 'NO_TOKEN'
        });
      }
      
      const token = authHeader.substring(7); // Remove 'Bearer ' prefix
      
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if user still exists and is active
        const user = await User.findById(decoded.userId);
        if (!user || user.status !== 'active') {
          return res.status(401).json({
            success: false,
            message: 'Token is valid but user account is inactive.',
            code: 'USER_INACTIVE'
          });
        }
        
        // Check if token was issued before last password change
        if (user.security.lastPasswordChange && 
            decoded.iat < Math.floor(user.security.lastPasswordChange.getTime() / 1000)) {
          return res.status(401).json({
            success: false,
            message: 'Token is invalid due to recent password change.',
            code: 'TOKEN_EXPIRED_PASSWORD_CHANGE'
          });
        }
        
        // Add user info to request
        req.user = {
          userId: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          permissions: user.permissions,
          mfaEnabled: user.mfa.enabled
        };
        
        next();
      } catch (jwtError) {
        if (jwtError.name === 'TokenExpiredError') {
          return res.status(401).json({
            success: false,
            message: 'Token has expired.',
            code: 'TOKEN_EXPIRED'
          });
        } else if (jwtError.name === 'JsonWebTokenError') {
          return res.status(401).json({
            success: false,
            message: 'Invalid token.',
            code: 'INVALID_TOKEN'
          });
        } else {
          throw jwtError;
        }
      }
    } catch (error) {
      console.error('Auth middleware error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during authentication.',
        code: 'AUTH_ERROR'
      });
    }
  }

  // Verify refresh token
  static async verifyRefreshToken(req, res, next) {
    try {
      const { refreshToken } = req.body;
      
      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          message: 'Refresh token required.',
          code: 'NO_REFRESH_TOKEN'
        });
      }
      
      try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        
        // Find user and check if refresh token exists
        const user = await User.findById(decoded.userId);
        if (!user) {
          return res.status(401).json({
            success: false,
            message: 'Invalid refresh token.',
            code: 'INVALID_REFRESH_TOKEN'
          });
        }
        
        const tokenRecord = user.refreshTokens.find(t => t.token === refreshToken);
        if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
          return res.status(401).json({
            success: false,
            message: 'Refresh token expired or invalid.',
            code: 'REFRESH_TOKEN_EXPIRED'
          });
        }
        
        req.user = {
          userId: user._id,
          username: user.username,
          email: user.email,
          role: user.role
        };
        
        next();
      } catch (jwtError) {
        return res.status(401).json({
          success: false,
          message: 'Invalid refresh token.',
          code: 'INVALID_REFRESH_TOKEN'
        });
      }
    } catch (error) {
      console.error('Refresh token verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during token refresh.',
        code: 'REFRESH_ERROR'
      });
    }
  }

  // Check if MFA is required and verified
  static async requireMFA(req, res, next) {
    try {
      const user = await User.findById(req.user.userId);
      
      if (user.mfa.enabled && !req.session?.mfaVerified) {
        return res.status(403).json({
          success: false,
          message: 'MFA verification required.',
          code: 'MFA_REQUIRED'
        });
      }
      
      next();
    } catch (error) {
      console.error('MFA middleware error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during MFA check.',
        code: 'MFA_ERROR'
      });
    }
  }

  // Role-based authorization
  static requireRole(...roles) {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required.',
          code: 'AUTH_REQUIRED'
        });
      }
      
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions.',
          code: 'INSUFFICIENT_PERMISSIONS',
          required: roles,
          current: req.user.role
        });
      }
      
      next();
    };
  }

  // Permission-based authorization
  static requirePermission(resource, action) {
    return async (req, res, next) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            success: false,
            message: 'Authentication required.',
            code: 'AUTH_REQUIRED'
          });
        }
        
        // Super admin has all permissions
        if (req.user.role === 'super_admin') {
          return next();
        }
        
        // Check user permissions
        const user = await User.findById(req.user.userId);
        const hasPermission = user.permissions.some(permission => 
          permission.resource === resource && 
          permission.actions.includes(action)
        );
        
        if (!hasPermission) {
          // Log unauthorized access attempt
          user.addAuditLog(
            'unauthorized_access_attempt',
            req.ip,
            req.get('User-Agent'),
            { resource, action, attempted: new Date() }
          );
          await user.save();
          
          return res.status(403).json({
            success: false,
            message: 'Permission denied for this resource.',
            code: 'PERMISSION_DENIED',
            required: { resource, action }
          });
        }
        
        next();
      } catch (error) {
        console.error('Permission middleware error:', error);
        res.status(500).json({
          success: false,
          message: 'Internal server error during permission check.',
          code: 'PERMISSION_ERROR'
        });
      }
    };
  }

  // Optional authentication (for public endpoints that can benefit from user context)
  static async optionalAuth(req, res, next) {
    try {
      const authHeader = req.header('Authorization');
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return next(); // Continue without authentication
      }
      
      const token = authHeader.substring(7);
      
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (user && user.status === 'active') {
          req.user = {
            userId: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            permissions: user.permissions
          };
        }
      } catch (jwtError) {
        // Ignore JWT errors for optional auth
      }
      
      next();
    } catch (error) {
      console.error('Optional auth middleware error:', error);
      next(); // Continue even if there's an error
    }
  }

  // Check account status
  static async checkAccountStatus(req, res, next) {
    try {
      if (!req.user) {
        return next();
      }
      
      const user = await User.findById(req.user.userId);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User account not found.',
          code: 'USER_NOT_FOUND'
        });
      }
      
      if (user.status === 'suspended') {
        return res.status(403).json({
          success: false,
          message: 'Account has been suspended.',
          code: 'ACCOUNT_SUSPENDED'
        });
      }
      
      if (user.status === 'inactive') {
        return res.status(403).json({
          success: false,
          message: 'Account is inactive.',
          code: 'ACCOUNT_INACTIVE'
        });
      }
      
      if (user.isLocked) {
        return res.status(423).json({
          success: false,
          message: 'Account is temporarily locked.',
          code: 'ACCOUNT_LOCKED',
          lockoutUntil: user.security.lockoutUntil
        });
      }
      
      next();
    } catch (error) {
      console.error('Account status middleware error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error during account status check.',
        code: 'ACCOUNT_STATUS_ERROR'
      });
    }
  }

  // Audit trail middleware
  static auditRequest() {
    return async (req, res, next) => {
      if (req.user) {
        try {
          const user = await User.findById(req.user.userId);
          if (user) {
            user.addAuditLog(
              `${req.method}_${req.path}`,
              req.ip,
              req.get('User-Agent'),
              {
                method: req.method,
                path: req.path,
                query: req.query,
                timestamp: new Date()
              }
            );
            await user.save();
          }
        } catch (error) {
          console.error('Audit middleware error:', error);
          // Don't block the request if audit fails
        }
      }
      next();
    };
  }
}

module.exports = AuthMiddleware;
