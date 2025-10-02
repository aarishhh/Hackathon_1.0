const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const speakeasy = require('speakeasy');

const userSchema = new mongoose.Schema({
  // Basic Information (encrypted)
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50,
    match: /^[a-zA-Z0-9_]+$/ // Only alphanumeric and underscore
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false // Don't include password in queries by default
  },
  
  // Government ID Information (encrypted)
  governmentId: {
    type: String,
    required: true,
    unique: true,
    // This will be encrypted before storing
  },
  governmentIdType: {
    type: String,
    required: true,
    enum: ['aadhaar', 'pan', 'passport', 'voter_id', 'driving_license']
  },
  
  // Personal Information (encrypted)
  personalInfo: {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    dateOfBirth: { type: Date, required: true },
    phoneNumber: { type: String, required: true },
    address: {
      street: String,
      city: String,
      state: String,
      pincode: String,
      country: { type: String, default: 'India' }
    }
  },
  
  // Role-Based Access Control
  role: {
    type: String,
    enum: ['citizen', 'officer', 'admin', 'super_admin'],
    default: 'citizen'
  },
  permissions: [{
    resource: String,
    actions: [String] // ['read', 'write', 'delete', 'update']
  }],
  
  // Security Features
  mfa: {
    enabled: { type: Boolean, default: false },
    secret: { type: String, select: false },
    backupCodes: [{ type: String, select: false }],
    lastUsed: Date
  },
  
  // Security Tracking
  security: {
    lastLogin: Date,
    lastPasswordChange: { type: Date, default: Date.now },
    failedLoginAttempts: { type: Number, default: 0 },
    lockoutUntil: Date,
    passwordHistory: [{ type: String, select: false }], // Store last 5 password hashes
    twoFactorBackupCodes: [{ type: String, select: false }]
  },
  
  // Audit Trail
  auditLog: [{
    action: String,
    timestamp: { type: Date, default: Date.now },
    ipAddress: String,
    userAgent: String,
    details: mongoose.Schema.Types.Mixed
  }],
  
  // Account Status
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'pending_verification'],
    default: 'pending_verification'
  },
  emailVerified: { type: Boolean, default: false },
  phoneVerified: { type: Boolean, default: false },
  
  // Refresh Token for JWT
  refreshTokens: [{
    token: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
    device: String,
    ipAddress: String
  }]
}, {
  timestamps: true,
  // Enable automatic indexing
  autoIndex: true
});

// Indexes for performance and security
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ governmentId: 1 });
userSchema.index({ 'security.lastLogin': -1 });
userSchema.index({ status: 1 });
userSchema.index({ role: 1 });

// Virtual for account lockout status
userSchema.virtual('isLocked').get(function() {
  return !!(this.security.lockoutUntil && this.security.lockoutUntil > Date.now());
});

// Pre-save middleware for password hashing
userSchema.pre('save', async function(next) {
  // Only hash password if it's been modified
  if (!this.isModified('password')) return next();
  
  try {
    // Check password strength
    if (!this.isPasswordStrong(this.password)) {
      throw new Error('Password does not meet security requirements');
    }
    
    // Hash password with salt rounds of 12
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    
    // Add to password history (keep last 5)
    if (this.security.passwordHistory.length >= 5) {
      this.security.passwordHistory.shift();
    }
    this.security.passwordHistory.push(this.password);
    this.security.lastPasswordChange = new Date();
    
    next();
  } catch (error) {
    next(error);
  }
});

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error('Password comparison failed');
  }
};

// Instance method to check password strength
userSchema.methods.isPasswordStrong = function(password) {
  // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
  const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return strongPasswordRegex.test(password);
};

// Instance method to handle failed login attempts
userSchema.methods.handleFailedLogin = async function() {
  this.security.failedLoginAttempts += 1;
  
  // Lock account after 5 failed attempts for 30 minutes
  if (this.security.failedLoginAttempts >= 5) {
    this.security.lockoutUntil = Date.now() + 30 * 60 * 1000; // 30 minutes
  }
  
  await this.save();
};

// Instance method to handle successful login
userSchema.methods.handleSuccessfulLogin = async function(ipAddress, userAgent) {
  this.security.lastLogin = new Date();
  this.security.failedLoginAttempts = 0;
  this.security.lockoutUntil = undefined;
  
  // Add to audit log
  this.auditLog.push({
    action: 'login',
    ipAddress,
    userAgent,
    details: { success: true }
  });
  
  await this.save();
};

// Instance method to generate MFA secret
userSchema.methods.generateMFASecret = function() {
  const secret = speakeasy.generateSecret({
    name: `${process.env.MFA_SERVICE_NAME} (${this.username})`,
    issuer: process.env.MFA_ISSUER || 'Government of India',
    length: 32
  });
  
  this.mfa.secret = secret.base32;
  return secret;
};

// Instance method to verify MFA token
userSchema.methods.verifyMFAToken = function(token) {
  if (!this.mfa.enabled || !this.mfa.secret) {
    return false;
  }
  
  return speakeasy.totp.verify({
    secret: this.mfa.secret,
    encoding: 'base32',
    token: token,
    window: 2 // Allow 2 time steps of variance
  });
};

// Instance method to generate backup codes for MFA
userSchema.methods.generateMFABackupCodes = function() {
  const codes = [];
  for (let i = 0; i < 10; i++) {
    codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
  }
  
  this.mfa.backupCodes = codes.map(code => 
    crypto.createHash('sha256').update(code).digest('hex')
  );
  
  return codes; // Return unhashed codes to display to user
};

// Instance method to use MFA backup code
userSchema.methods.useMFABackupCode = function(code) {
  const hashedCode = crypto.createHash('sha256').update(code).digest('hex');
  const index = this.mfa.backupCodes.indexOf(hashedCode);
  
  if (index !== -1) {
    this.mfa.backupCodes.splice(index, 1);
    return true;
  }
  
  return false;
};

// Instance method to add audit log entry
userSchema.methods.addAuditLog = function(action, ipAddress, userAgent, details = {}) {
  this.auditLog.push({
    action,
    ipAddress,
    userAgent,
    details
  });
  
  // Keep only last 100 audit entries
  if (this.auditLog.length > 100) {
    this.auditLog = this.auditLog.slice(-100);
  }
};

// Static method to find user by credentials
userSchema.statics.findByCredentials = async function(username, password) {
  const user = await this.findOne({
    $or: [{ username }, { email: username }],
    status: { $in: ['active', 'pending_verification'] }
  }).select('+password');
  
  if (!user) {
    throw new Error('Invalid credentials');
  }
  
  if (user.isLocked) {
    throw new Error('Account is temporarily locked due to multiple failed login attempts');
  }
  
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    await user.handleFailedLogin();
    throw new Error('Invalid credentials');
  }
  
  return user;
};

// Remove sensitive data when converting to JSON
userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  
  // Remove sensitive fields
  delete userObject.password;
  delete userObject.mfa.secret;
  delete userObject.mfa.backupCodes;
  delete userObject.security.passwordHistory;
  delete userObject.security.twoFactorBackupCodes;
  delete userObject.refreshTokens;
  
  // Limit audit log to last 10 entries for JSON response
  if (userObject.auditLog && userObject.auditLog.length > 10) {
    userObject.auditLog = userObject.auditLog.slice(-10);
  }
  
  return userObject;
};

module.exports = mongoose.model('User', userSchema);
