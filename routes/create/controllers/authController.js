import express from 'express';
import AuthService from '../services/authService.js';
// import { validateLogin, validateRegister } from '../middleware/validator.js';
import { authenticateToken } from '../middleware/auth.js';
import { successResponse, errorResponse, unauthorizedResponse } from '../utils/responseFormatter.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { HTTP_STATUS } from '../config/constants.js';
import { passport, samlStrategy } from '../middleware/passport.js';

const router = express.Router();

/**
 * POST /api/auth/login
 * Authenticate user with CWL credentials
 */
router.post('/login', asyncHandler(async (req, res) => {
  const { cwlId, password } = req.body;

  const result = await AuthService.authenticate(cwlId, password);

  if (result.success) {
    // Set refresh token as httpOnly cookie
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    return successResponse(res, {
      user: result.user,
      accessToken: result.tokens.accessToken
    }, 'Login successful');
  } else {
    return unauthorizedResponse(res, result.message);
  }
}));

/**
 * POST /api/auth/register
 * Register a new user with CWL credentials
 */
router.post('/register', asyncHandler(async (req, res) => {
  const { cwlId, password } = req.body;

  const result = await AuthService.register(cwlId, password);

  if (result.success) {
    // Set refresh token as httpOnly cookie
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    return successResponse(res, {
      user: result.user,
      accessToken: result.tokens.accessToken
    }, 'Registration successful', HTTP_STATUS.CREATED);
  } else {
    return errorResponse(res, result.message, 'REGISTRATION_ERROR', HTTP_STATUS.BAD_REQUEST);
  }
}));

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
router.post('/refresh', asyncHandler(async (req, res) => {
  const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

  if (!refreshToken) {
    return unauthorizedResponse(res, 'Refresh token required');
  }

  const result = await AuthService.refreshToken(refreshToken);

  if (result.success) {
    return successResponse(res, {
      accessToken: result.accessToken
    }, 'Token refreshed successfully');
  } else {
    // Clear invalid refresh token cookie
    res.clearCookie('refreshToken');
    return unauthorizedResponse(res, result.message);
  }
}));

/**
 * POST /api/auth/logout
 * Logout user and invalidate tokens
 */
router.post('/logout', authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;

  const result = await AuthService.logout(userId);

  // Clear refresh token cookie
  res.clearCookie('refreshToken');

  if (result.success) {
    return successResponse(res, null, 'Logout successful');
  } else {
    return errorResponse(res, result.message, 'LOGOUT_ERROR');
  }
}));

/**
 * GET /api/auth/logout
 * Logout user via SAML Single Logout
 */
router.get('/logout', (req, res, next) => {
  if (!req.user && !req.session.passport) {
    // No active session, just redirect to login
    return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:8090'}/login`);
  }

  // Initiate SAML Single Logout
  
  samlStrategy.logout(req, (err, requestUrl) => {
    if (err) {
      console.error('SAML logout error:', err);
      // Fallback: clear local session and redirect
      req.session.destroy(() => {
        res.clearCookie('refreshToken');
        res.clearCookie('accessToken');
        res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:8090'}/login`);
      });
      return;
    }

    // Clear local session and cookies
    req.logout((logoutErr) => {
      if (logoutErr) {
        console.error('Passport logout error:', logoutErr);
      }
      
      req.session.destroy((sessionErr) => {
        if (sessionErr) {
          console.error('Session destruction error:', sessionErr);
        }
        
        // Clear cookies
        res.clearCookie('refreshToken');
        res.clearCookie('accessToken');
        
        // Redirect to SAML IdP logout URL to clear IdP session
        res.redirect(requestUrl);
      });
    });
  });
});

/**
 * GET /api/auth/logout/callback
 * Handle SAML logout response from IdP
 */
router.get('/logout/callback', (req, res) => {
  // The SAML IdP has processed the logout
  // Clear any remaining session data and redirect to login
  res.clearCookie('refreshToken');
  res.clearCookie('accessToken');
  
  if (req.session) {
    req.session.destroy(() => {
      res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:8090'}/login`);
    });
  } else {
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:8090'}/login`);
  }
});

/**
 * GET /api/auth/me
 * Get current user profile
 */
router.get('/me', asyncHandler(async (req, res) => {
  // Check for authentication without throwing error
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1];
  
  // If no header token, check cookies
  if (!token && req.cookies.accessToken) {
    token = req.cookies.accessToken;
  }
  
  if (!token) {
    return res.status(200).json({
      authenticated: false
    });
  }
  
  // Verify token
  const decoded = AuthService.verifyToken(token);
  if (!decoded) {
    return res.status(200).json({
      authenticated: false
    });
  }
  
  // Validate session
  const isValidSession = await AuthService.validateSession(decoded.userId, decoded.tokenVersion);
  if (!isValidSession) {
    return res.status(200).json({
      authenticated: false
    });
  }
  const userId = decoded.userId;
  
  // Get full user details
  const User = (await import('../models/User.js')).default;
  const user = await User.findById(userId).select('-password');

  if (!user) {
    return res.status(200).json({
      authenticated: false
    });
  }

  // Update last activity
  await user.updateLastActivity();

  return res.status(200).json({
    authenticated: true,
    user: {
      id: user._id,
      cwlId: user.cwlId,
      stats: user.stats,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt
    }
  });
}));

/**
 * GET /api/auth/saml/login
 * Initiate SAML login
 */
router.get('/saml/login', passport.authenticate('saml', {
  failureRedirect: '/login?error=saml_failed'
}));

/**
 * POST /api/auth/saml/callback
 * SAML callback endpoint
 */
router.post('/saml/callback', 
  passport.authenticate('saml', { failureRedirect: '/login?error=auth_failed' }),
  asyncHandler(async (req, res) => {
    // Authentication successful
    // Generate JWT tokens
    const user = req.user;
    const result = await AuthService.generateTokens(user);
    
    // Set refresh token as httpOnly cookie
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    // Set access token as well for easier frontend access
    res.cookie('accessToken', result.tokens.accessToken, {
      httpOnly: false, // Allow JavaScript access for API calls
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });
    
    // Redirect to frontend dashboard
    res.redirect(process.env.FRONTEND_URL || 'http://localhost:8090');
  })
);

/**
 * POST /api/auth/validate
 * Validate current session/token
 */
router.post('/validate', authenticateToken, asyncHandler(async (req, res) => {
  // If we reach here, the token is valid (authenticateToken middleware passed)
  return successResponse(res, {
    valid: true,
    user: {
      id: req.user.id,
      cwlId: req.user.cwlId
    }
  }, 'Token is valid');
}));

export default router;