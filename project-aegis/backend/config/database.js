const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

class DatabaseManager {
  constructor() {
    this.connection = null;
    this.encryptionKey = process.env.DB_ENCRYPTION_KEY;
  }

  async connect() {
    try {
      const options = {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        family: 4, // Use IPv4, skip trying IPv6
        // Security options
        ssl: process.env.NODE_ENV === 'production',
        sslValidate: process.env.NODE_ENV === 'production',
      };

      this.connection = await mongoose.connect(process.env.MONGODB_URI, options);
      console.log('🔐 Database connected securely');
      
      // Set up connection event handlers
      mongoose.connection.on('error', this.handleError);
      mongoose.connection.on('disconnected', this.handleDisconnection);
      
      return this.connection;
    } catch (error) {
      console.error('❌ Database connection failed:', error.message);
      throw error;
    }
  }

  handleError(error) {
    console.error('🚨 Database error:', error);
  }

  handleDisconnection() {
    console.warn('⚠️ Database disconnected');
  }

  // Encryption utilities for sensitive data
  encryptData(text) {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not configured');
    }
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-cbc', this.encryptionKey);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
      encrypted,
      iv: iv.toString('hex')
    };
  }

  decryptData(encryptedData, iv) {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not configured');
    }
    
    const decipher = crypto.createDecipher('aes-256-cbc', this.encryptionKey);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  async disconnect() {
    if (this.connection) {
      await mongoose.disconnect();
      console.log('🔒 Database connection closed securely');
    }
  }
}

module.exports = new DatabaseManager();
