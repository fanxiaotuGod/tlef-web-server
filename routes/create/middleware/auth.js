import AuthService from '../services/authService.js';
import { HTTP_STATUS, ERROR_CODES } from '../config/constants.js';
import User from '../models/User.js';

/**
 * Middleware to authenticate JWT tokens
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
export const authenticateToken = async (req, res, next) => {
  try {
    // Check for token in Authorization header or cookies
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    // If no header token, check cookies
    if (!token && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        error: {
          code: ERROR_CODES.AUTH_ERROR,
          message: 'Access token required',
          timestamp: new Date().toISOString()
        }
      });
    }

    // Verify token
    const decoded = AuthService.verifyToken(token);
    if (!decoded) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        error: {
          code: ERROR_CODES.AUTH_ERROR,
          message: 'Invalid or expired token',
          timestamp: new Date().toISOString()
        }
      });
    }

    // Validate session
    const isValidSession = await AuthService.validateSession(decoded.userId, decoded.tokenVersion);
    if (!isValidSession) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({
        error: {
          code: ERROR_CODES.AUTH_ERROR,
          message: 'Session expired or invalid',
          timestamp: new Date().toISOString()
        }
      });
    }

    // Add user info to request
    req.user = {
      id: decoded.userId,
      cwlId: decoded.cwlId,
      tokenVersion: decoded.tokenVersion
    };

    next();
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
      error: {
        code: ERROR_CODES.AUTH_ERROR,
        message: 'Authentication failed',
        timestamp: new Date().toISOString()
      }
    });
  }
};

/**
 * Middleware to get full user object and attach to request
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
export const attachUser = async (req, res, next) => {
  try {
    if (req.user && req.user.id) {
      const fullUser = await User.findById(req.user.id).select('-password');
      if (fullUser) {
        req.user.fullUser = fullUser;
        
        // Update last activity
        await fullUser.updateLastActivity();
      }
    }
    next();
  } catch (error) {
    console.error('Attach user middleware error:', error);
    // Don't fail the request if we can't attach user, just log and continue
    next();
  }
};

/**
 * Middleware to check if user owns a resource
 * @param {string} resourceField - Field name that contains the user ID (default: 'createdBy')
 * @returns {Function} - Express middleware function
 */
export const checkResourceOwnership = (resourceField = 'createdBy') => {
  return async (req, res, next) => {
    try {
      const resourceId = req.params.id;
      const userId = req.user.id;

      // The specific model check should be done in the controller
      // This middleware just ensures the user is authenticated
      // and the resource exists in the request
      
      if (!resourceId) {
        return res.status(HTTP_STATUS.BAD_REQUEST).json({
          error: {
            code: ERROR_CODES.VALIDATION_ERROR,
            message: 'Resource ID required',
            timestamp: new Date().toISOString()
          }
        });
      }

      req.resourceId = resourceId;
      req.resourceField = resourceField;
      next();
    } catch (error) {
      console.error('Resource ownership middleware error:', error);
      return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
        error: {
          code: ERROR_CODES.AUTH_ERROR,
          message: 'Authorization check failed',
          timestamp: new Date().toISOString()
        }
      });
    }
  };
};

/**
 * Middleware to extract user ID from token without full authentication
 * Used for optional authentication scenarios
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = AuthService.verifyToken(token);
      if (decoded) {
        const isValidSession = await AuthService.validateSession(decoded.userId, decoded.tokenVersion);
        if (isValidSession) {
          req.user = {
            id: decoded.userId,
            cwlId: decoded.cwlId,
            tokenVersion: decoded.tokenVersion
          };
        }
      }
    }

    next();
  } catch (error) {
    console.error('Optional auth middleware error:', error);
    // Don't fail the request for optional auth, just continue without user
    next();
  }
};