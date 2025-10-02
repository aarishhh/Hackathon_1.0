const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const compression = require('compression');

class SecurityConfig {
  // Rate limiting configuration
  static getRateLimiter() {
    return rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
      message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
      },
      standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
      legacyHeaders: false, // Disable the `X-RateLimit-*` headers
      // Store rate limit data in memory (use Redis in production)
      store: undefined,
      // Skip rate limiting for trusted IPs (configure as needed)
      skip: (req) => {
        // Skip rate limiting for health checks
        return req.path === '/health';
      }
    });
  }

  // Strict rate limiter for authentication endpoints
  static getAuthRateLimiter() {
    return rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // limit each IP to 5 login requests per windowMs
      message: {
        error: 'Too many login attempts, please try again later.',
        code: 'AUTH_RATE_LIMIT_EXCEEDED'
      },
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: true, // Don't count successful requests
    });
  }

  // Helmet configuration for security headers
  static getHelmetConfig() {
    return helmet({
      // Content Security Policy
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
      // HTTP Strict Transport Security
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
      },
      // X-Frame-Options
      frameguard: { action: 'deny' },
      // X-Content-Type-Options
      noSniff: true,
      // X-XSS-Protection
      xssFilter: true,
      // Referrer Policy
      referrerPolicy: { policy: 'same-origin' },
      // Hide X-Powered-By header
      hidePoweredBy: true,
      // Permissions Policy
      permissionsPolicy: {
        features: {
          camera: ["'none'"],
          microphone: ["'none'"],
          geolocation: ["'self'"],
          notifications: ["'self'"],
        }
      }
    });
  }

  // CORS configuration
  static getCorsConfig() {
    return {
      origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
          process.env.CORS_ORIGIN || 'http://localhost:5173',
          'http://localhost:3000', // React dev server alternative
          'https://your-production-domain.gov.in' // Add your production domain
        ];
        
        if (allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS policy'));
        }
      },
      credentials: true, // Allow cookies and authorization headers
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-CSRF-Token',
        'Accept',
        'Origin'
      ],
      exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining'],
      maxAge: 86400 // 24 hours
    };
  }

  // MongoDB injection prevention
  static getMongoSanitize() {
    return mongoSanitize({
      replaceWith: '_',
      onSanitize: ({ req, key }) => {
        console.warn(`🚨 Potential NoSQL injection attempt detected: ${key}`);
      }
    });
  }

  // HTTP Parameter Pollution prevention
  static getHppConfig() {
    return hpp({
      whitelist: ['sort', 'fields', 'page', 'limit'] // Allow these parameters to be arrays
    });
  }

  // Compression configuration
  static getCompression() {
    return compression({
      filter: (req, res) => {
        // Don't compress responses if the client doesn't support it
        if (req.headers['x-no-compression']) {
          return false;
        }
        // Use compression for all other responses
        return compression.filter(req, res);
      },
      level: 6, // Compression level (1-9, 6 is default)
      threshold: 1024, // Only compress if response is larger than 1KB
    });
  }

  // Security headers middleware
  static securityHeaders() {
    return (req, res, next) => {
      // Additional custom security headers
      res.setHeader('X-API-Version', '1.0');
      res.setHeader('X-Response-Time', Date.now());
      
      // Remove server information
      res.removeHeader('X-Powered-By');
      res.removeHeader('Server');
      
      next();
    };
  }

  // Request logging for security audit
  static securityLogger() {
    return (req, res, next) => {
      const securityInfo = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        contentType: req.get('Content-Type'),
        contentLength: req.get('Content-Length')
      };
      
      // Log suspicious patterns
      const suspiciousPatterns = [
        /script/i, /javascript/i, /vbscript/i, /onload/i, /onerror/i,
        /union/i, /select/i, /insert/i, /delete/i, /drop/i, /exec/i,
        /<script/i, /javascript:/i, /vbscript:/i, /data:/i
      ];
      
      const requestData = JSON.stringify(req.body) + req.url + (req.query ? JSON.stringify(req.query) : '');
      
      const hasSuspiciousContent = suspiciousPatterns.some(pattern => 
        pattern.test(requestData)
      );
      
      if (hasSuspiciousContent) {
        console.warn('🚨 Suspicious request detected:', securityInfo);
      }
      
      next();
    };
  }
}

module.exports = SecurityConfig;
