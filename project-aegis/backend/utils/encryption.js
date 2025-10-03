const crypto = require('crypto');
require('dotenv').config();

class EncryptionService {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32; // 256 bits
    this.ivLength = 16;  // 128 bits
    this.saltLength = 32; // 256 bits
    this.tagLength = 16; // 128 bits
    
    // Get encryption key from environment or generate a demo key
    this.encryptionKey = process.env.AES_ENCRYPTION_KEY;
    if (!this.encryptionKey) {
      console.warn('⚠️ AES encryption key not configured. Generating demo key.');
      this.encryptionKey = EncryptionService.generateKey();
    }
    if (this.encryptionKey.length !== 64) { // 32 bytes = 64 hex chars
      console.warn('⚠️ AES encryption key length incorrect. Generating new key.');
      this.encryptionKey = EncryptionService.generateKey();
    }
  }

  // Generate a random encryption key
  static generateKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  // Generate a random IV
  generateIV() {
    return crypto.randomBytes(this.ivLength);
  }

  // Generate a random salt
  generateSalt() {
    return crypto.randomBytes(this.saltLength);
  }

  // Derive key from password using PBKDF2
  deriveKey(password, salt, iterations = 100000) {
    return crypto.pbkdf2Sync(password, salt, iterations, this.keyLength, 'sha256');
  }

  // Encrypt data with AES-256-GCM
  encrypt(plaintext, key = null) {
    try {
      const encryptionKey = key || Buffer.from(this.encryptionKey, 'hex');
      const iv = this.generateIV();
      
      const cipher = crypto.createCipher(this.algorithm, encryptionKey, iv);
      
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      // Return encrypted data with IV and auth tag
      return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
      };
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  // Decrypt data with AES-256-GCM
  decrypt(encryptedData, key = null) {
    try {
      const encryptionKey = key || Buffer.from(this.encryptionKey, 'hex');
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const authTag = Buffer.from(encryptedData.authTag, 'hex');
      
      const decipher = crypto.createDecipher(this.algorithm, encryptionKey, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  // Encrypt sensitive user data
  encryptUserData(data) {
    if (typeof data === 'object') {
      data = JSON.stringify(data);
    }
    return this.encrypt(data);
  }

  // Decrypt sensitive user data
  decryptUserData(encryptedData) {
    const decrypted = this.decrypt(encryptedData);
    try {
      return JSON.parse(decrypted);
    } catch {
      return decrypted;
    }
  }

  // Hash data with SHA-256
  hash(data, salt = null) {
    const actualSalt = salt || this.generateSalt();
    const hash = crypto.createHash('sha256');
    hash.update(data + actualSalt.toString('hex'));
    
    return {
      hash: hash.digest('hex'),
      salt: actualSalt.toString('hex')
    };
  }

  // Verify hash
  verifyHash(data, hashedData, salt) {
    const hash = crypto.createHash('sha256');
    hash.update(data + salt);
    return hash.digest('hex') === hashedData;
  }

  // Generate HMAC for data integrity
  generateHMAC(data, secret = null) {
    const hmacSecret = secret || this.encryptionKey;
    const hmac = crypto.createHmac('sha256', hmacSecret);
    hmac.update(data);
    return hmac.digest('hex');
  }

  // Verify HMAC
  verifyHMAC(data, signature, secret = null) {
    const expectedSignature = this.generateHMAC(data, secret);
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  }

  // Encrypt file data
  encryptFile(fileBuffer) {
    try {
      const key = crypto.randomBytes(this.keyLength);
      const iv = this.generateIV();
      
      const cipher = crypto.createCipher(this.algorithm, key, iv);
      
      const encrypted = Buffer.concat([
        cipher.update(fileBuffer),
        cipher.final()
      ]);
      
      const authTag = cipher.getAuthTag();
      
      return {
        encryptedData: encrypted,
        key: key.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
      };
    } catch (error) {
      console.error('File encryption error:', error);
      throw new Error('Failed to encrypt file');
    }
  }

  // Decrypt file data
  decryptFile(encryptedFile) {
    try {
      const key = Buffer.from(encryptedFile.key, 'hex');
      const iv = Buffer.from(encryptedFile.iv, 'hex');
      const authTag = Buffer.from(encryptedFile.authTag, 'hex');
      
      const decipher = crypto.createDecipher(this.algorithm, key, iv);
      decipher.setAuthTag(authTag);
      
      const decrypted = Buffer.concat([
        decipher.update(encryptedFile.encryptedData),
        decipher.final()
      ]);
      
      return decrypted;
    } catch (error) {
      console.error('File decryption error:', error);
      throw new Error('Failed to decrypt file');
    }
  }

  // Generate secure random token
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Generate cryptographically secure random number
  generateSecureRandom(min = 0, max = 1000000) {
    const range = max - min + 1;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8);
    const maxValidValue = Math.floor(256 ** bytesNeeded / range) * range - 1;
    
    let randomValue;
    do {
      const randomBytes = crypto.randomBytes(bytesNeeded);
      randomValue = randomBytes.readUIntBE(0, bytesNeeded);
    } while (randomValue > maxValidValue);
    
    return min + (randomValue % range);
  }

  // Key derivation for password-based encryption
  deriveKeyFromPassword(password, salt = null, iterations = 100000) {
    const actualSalt = salt || this.generateSalt();
    const derivedKey = crypto.pbkdf2Sync(
      password,
      actualSalt,
      iterations,
      this.keyLength,
      'sha256'
    );
    
    return {
      key: derivedKey,
      salt: actualSalt,
      iterations
    };
  }

  // Secure data comparison (timing attack resistant)
  secureCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    
    return crypto.timingSafeEqual(
      Buffer.from(a, 'utf8'),
      Buffer.from(b, 'utf8')
    );
  }

  // Generate digital signature
  generateSignature(data, privateKey) {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(data);
    return sign.sign(privateKey, 'hex');
  }

  // Verify digital signature
  verifySignature(data, signature, publicKey) {
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(data);
    return verify.verify(publicKey, signature, 'hex');
  }

  // Generate RSA key pair for digital signatures
  generateRSAKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
  }

  // Encrypt data for database storage
  encryptForDatabase(data) {
    const stringData = typeof data === 'string' ? data : JSON.stringify(data);
    const encrypted = this.encrypt(stringData);
    
    // Return base64 encoded string for easy database storage
    return Buffer.from(JSON.stringify(encrypted)).toString('base64');
  }

  // Decrypt data from database storage
  decryptFromDatabase(encryptedBase64) {
    try {
      const encryptedData = JSON.parse(Buffer.from(encryptedBase64, 'base64').toString());
      const decrypted = this.decrypt(encryptedData);
      
      // Try to parse as JSON, return as string if it fails
      try {
        return JSON.parse(decrypted);
      } catch {
        return decrypted;
      }
    } catch (error) {
      console.error('Database decryption error:', error);
      throw new Error('Failed to decrypt data from database');
    }
  }
}

// Export singleton instance
module.exports = new EncryptionService();
