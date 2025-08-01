import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { JWT_CONFIG } from '../config/constants.js';
import User from '../models/User.js';
import { redisUtils } from '../config/redis.js';

class AuthService {
  /**
   * Hash a password using bcrypt
   * @param {string} password - Plain text password
   * @returns {Promise<string>} - Hashed password
   */
  static async hashPassword(password) {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }

  /**
   * Compare a plain text password with a hashed password
   * @param {string} password - Plain text password
   * @param {string} hashedPassword - Hashed password
   * @returns {Promise<boolean>} - True if passwords match
   */
  static async comparePassword(password, hashedPassword) {
    return bcrypt.compare(password, hashedPassword);
  }

  /**
   * Generate JWT access token
   * @param {Object} payload - Token payload
   * @returns {string} - JWT token
   */
  static generateAccessToken(payload) {
    return jwt.sign(payload, JWT_CONFIG.SECRET, {
      expiresIn: JWT_CONFIG.ACCESS_TOKEN_EXPIRY
    });
  }

  /**
   * Generate JWT refresh token
   * @param {Object} payload - Token payload
   * @returns {string} - JWT refresh token
   */
  static generateRefreshToken(payload) {
    return jwt.sign(payload, JWT_CONFIG.SECRET, {
      expiresIn: JWT_CONFIG.REFRESH_TOKEN_EXPIRY
    });
  }

  /**
   * Verify JWT token
   * @param {string} token - JWT token
   * @returns {Object|null} - Decoded token or null if invalid
   */
  static verifyToken(token) {
    try {
      return jwt.verify(token, JWT_CONFIG.SECRET);
    } catch (error) {
      return null;
    }
  }

  /**
   * Generate both access and refresh tokens
   * @param {Object} user - User object
   * @returns {Object} - Object containing both tokens
   */
  static generateTokens(user) {
    const payload = {
      userId: user._id,
      cwlId: user.cwlId,
      tokenVersion: user.tokenVersion
    };

    const accessToken = this.generateAccessToken(payload);
    const refreshToken = this.generateRefreshToken(payload);

    return { accessToken, refreshToken };
  }

  /**
   * Authenticate user with CWL credentials
   * @param {string} cwlId - CWL ID
   * @param {string} password - Password
   * @returns {Promise<Object>} - Authentication result
   */
  static async authenticate(cwlId, password) {
    try {
      // Find user by CWL ID
      const user = await User.findOne({ cwlId });
      if (!user) {
        return {
          success: false,
          message: 'Invalid CWL ID or password'
        };
      }

      // Check password
      const isPasswordValid = await this.comparePassword(password, user.password);
      if (!isPasswordValid) {
        return {
          success: false,
          message: 'Invalid CWL ID or password'
        };
      }

      // Update last login
      await user.updateLastLogin();

      // Generate tokens
      const tokens = this.generateTokens(user);

      // Store session in Redis
      await redisUtils.setSession(user._id.toString(), {
        cwlId: user.cwlId,
        tokenVersion: user.tokenVersion,
        loginTime: new Date()
      }, 7 * 24 * 60 * 60); // 7 days

      return {
        success: true,
        user: {
          id: user._id,
          cwlId: user.cwlId,
          stats: user.stats,
          lastLogin: user.lastLogin
        },
        tokens
      };
    } catch (error) {
      console.error('Authentication error:', error);
      return {
        success: false,
        message: 'Authentication failed'
      };
    }
  }

  /**
   * Register a new user
   * @param {string} cwlId - CWL ID
   * @param {string} password - Password
   * @returns {Promise<Object>} - Registration result
   */
  static async register(cwlId, password) {
    try {
      // Check if user already exists
      const existingUser = await User.findOne({ cwlId });
      if (existingUser) {
        return {
          success: false,
          message: 'User with this CWL ID already exists'
        };
      }

      // Hash password
      const hashedPassword = await this.hashPassword(password);

      // Create new user
      const user = new User({
        cwlId,
        password: hashedPassword
      });

      await user.save();

      // Generate tokens
      const tokens = this.generateTokens(user);

      // Store session in Redis
      await redisUtils.setSession(user._id.toString(), {
        cwlId: user.cwlId,
        tokenVersion: user.tokenVersion,
        loginTime: new Date()
      }, 7 * 24 * 60 * 60); // 7 days

      return {
        success: true,
        user: {
          id: user._id,
          cwlId: user.cwlId,
          stats: user.stats,
          lastLogin: user.lastLogin
        },
        tokens
      };
    } catch (error) {
      console.error('Registration error:', error);
      return {
        success: false,
        message: 'Registration failed'
      };
    }
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @returns {Promise<Object>} - Refresh result
   */
  static async refreshToken(refreshToken) {
    try {
      // Verify refresh token
      const decoded = this.verifyToken(refreshToken);
      if (!decoded) {
        return {
          success: false,
          message: 'Invalid refresh token'
        };
      }

      // Find user and check token version
      const user = await User.findById(decoded.userId);
      if (!user || user.tokenVersion !== decoded.tokenVersion) {
        return {
          success: false,
          message: 'Invalid refresh token'
        };
      }

      // Check if session exists in Redis
      const session = await redisUtils.getSession(user._id.toString());
      if (!session) {
        return {
          success: false,
          message: 'Session expired'
        };
      }

      // Generate new access token
      const accessToken = this.generateAccessToken({
        userId: user._id,
        cwlId: user.cwlId,
        tokenVersion: user.tokenVersion
      });

      return {
        success: true,
        accessToken
      };
    } catch (error) {
      console.error('Token refresh error:', error);
      return {
        success: false,
        message: 'Token refresh failed'
      };
    }
  }

  /**
   * Generate both access and refresh tokens for a user
   * @param {Object} user - User object
   * @returns {Promise<Object>} - Tokens and user data
   */
  static async generateTokens(user) {
    try {
      const payload = {
        userId: user._id,
        cwlId: user.cwlId,
        tokenVersion: user.tokenVersion || 0
      };

      const accessToken = this.generateAccessToken(payload);
      const refreshToken = this.generateRefreshToken(payload);

      // Store session in Redis
      await redisUtils.setSession(user._id.toString(), {
        userId: user._id,
        cwlId: user.cwlId,
        createdAt: Date.now()
      });

      return {
        success: true,
        tokens: {
          accessToken,
          refreshToken
        },
        user: {
          id: user._id,
          cwlId: user.cwlId,
          stats: user.stats
        }
      };
    } catch (error) {
      console.error('Token generation error:', error);
      return {
        success: false,
        message: 'Token generation failed'
      };
    }
  }

  /**
   * Logout user
   * @param {string} userId - User ID
   * @returns {Promise<Object>} - Logout result
   */
  static async logout(userId) {
    try {
      // Remove session from Redis
      await redisUtils.deleteSession(userId);

      // Increment token version to invalidate all existing tokens
      const user = await User.findById(userId);
      if (user) {
        await user.incrementTokenVersion();
      }

      return {
        success: true,
        message: 'Logged out successfully'
      };
    } catch (error) {
      console.error('Logout error:', error);
      return {
        success: false,
        message: 'Logout failed'
      };
    }
  }

  /**
   * Validate user session
   * @param {string} userId - User ID
   * @param {number} tokenVersion - Token version
   * @returns {Promise<boolean>} - True if session is valid
   */
  static async validateSession(userId, tokenVersion) {
    try {
      // Check session in Redis
      const session = await redisUtils.getSession(userId);
      if (!session) {
        return false;
      }

      // Check token version
      const user = await User.findById(userId);
      if (!user || user.tokenVersion !== tokenVersion) {
        return false;
      }

      return true;
    } catch (error) {
      console.error('Session validation error:', error);
      return false;
    }
  }
}

export default AuthService;