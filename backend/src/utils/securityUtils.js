const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

/**
 * Gets the encryption key from environment variables
 * and derives a consistent 32-byte key.
 */
const getSecretKey = () => {
    if (!process.env.ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY is not configured in environment variables');
    }

    const rawKey = process.env.ENCRYPTION_KEY;
    return crypto.createHash('sha256').update(rawKey).digest();
};

/**
 * Gets the JWT secret from environment variables.
 */
const getJWTSecret = () => {
    if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET is not configured in environment variables');
    }

    return process.env.JWT_SECRET;
};

/**
 * Hash a plain text password using bcryptjs
 * @param {string} password
 * @returns {Promise<string>} hashed password
 */
const hashPassword = async (password) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
};

/**
 * Compare plain text password against the hashed password
 * @param {string} password
 * @param {string} hashed
 * @returns {Promise<boolean>} match status
 */
const comparePassword = async (password, hashed) => {
    return await bcrypt.compare(password, hashed);
};

/**
 * Generate a JWT token signed with user scope
 * @param {Object} user
 * @returns {string} JWT Token
 */
const generateToken = (user) => {
    return jwt.sign(
        {
            id: user.id || user._id,
            role: user.role,
            name: user.name,
            personalNo: user.personalNo
        },
        getJWTSecret(),
        { expiresIn: '30d' }
    );
};

/**
 * Verify a JWT token
 * @param {string} token
 * @returns {Object} decoded token payload
 */
const verifyToken = (token) => {
    return jwt.verify(token, getJWTSecret());
};

/**
 * Encrypt plain text using AES-256-CBC
 * @param {string} text
 * @returns {string} encrypted cipher text (format: iv:encryptedHex)
 */
const encryptData = (text) => {
    if (!text) return text;

    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, getSecretKey(), iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return iv.toString('hex') + ':' + encrypted;
    } catch (err) {
        console.error('Encryption failed:', err.message);
        return text;
    }
};

/**
 * Decrypt cipher text using AES-256-CBC
 * @param {string} encryptedText
 * @returns {string} decrypted plain text
 */
const decryptData = (encryptedText) => {
    if (!encryptedText) return encryptedText;

    try {
        const parts = encryptedText.split(':');

        if (parts.length !== 2) {
            // Text is not in iv:encryptedHex format
            return encryptedText;
        }

        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedHex = Buffer.from(parts.join(':'), 'hex');

        const decipher = crypto.createDecipheriv(
            ALGORITHM,
            getSecretKey(),
            iv
        );

        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (err) {
        console.error('Decryption failed:', err.message);
        return encryptedText;
    }
};

/**
 * Helper to serialize and encrypt objects
 * @param {Object} obj
 * @returns {string} encrypted text
 */
const encryptObject = (obj) => {
    if (!obj) return obj;

    try {
        const text = JSON.stringify(obj);
        return encryptData(text);
    } catch (err) {
        console.error(
            'Object serialization and encryption failed:',
            err.message
        );
        return obj;
    }
};

/**
 * Helper to decrypt and deserialize objects
 * @param {string} encryptedText
 * @returns {Object} decrypted object
 */
const decryptObject = (encryptedText) => {
    if (!encryptedText) return encryptedText;

    if (
        typeof encryptedText !== 'string' ||
        !encryptedText.includes(':')
    ) {
        // Not encrypted or already an object
        return encryptedText;
    }

    try {
        const decryptedText = decryptData(encryptedText);
        return JSON.parse(decryptedText);
    } catch (err) {
        console.error(
            'Object decryption and deserialization failed:',
            err.message
        );
        return encryptedText;
    }
};

module.exports = {
    hashPassword,
    comparePassword,
    generateToken,
    verifyToken,
    encryptData,
    decryptData,
    encryptObject,
    decryptObject
};