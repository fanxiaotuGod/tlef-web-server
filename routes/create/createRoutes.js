import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { RATE_LIMITS, HTTP_STATUS, ERROR_CODES } from './config/constants.js';
import { errorResponse } from './utils/responseFormatter.js';

// Import controllers
import authController from './controllers/authController.js';
// import folderController from './controllers/folderController.js';
// import materialController from './controllers/materialController.js';
// import quizController from './controllers/quizController.js';
// import objectiveController from './controllers/objectiveController.js';
// import planController from './controllers/planController.js';
// import questionController from './controllers/questionController.js';
// import exportController from './controllers/exportController.js';

const router = express.Router();

// Security middleware
router.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: RATE_LIMITS.AUTH.windowMs,
  max: RATE_LIMITS.AUTH.max,
  message: {
    error: {
      code: ERROR_CODES.AUTH_ERROR,
      message: 'Too many authentication attempts, please try again later',
      timestamp: new Date().toISOString()
    }
  },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: RATE_LIMITS.API.windowMs,
  max: RATE_LIMITS.API.max,
  message: {
    error: {
      code: ERROR_CODES.VALIDATION_ERROR,
      message: 'Too many requests, please try again later',
      timestamp: new Date().toISOString()
    }
  },
  standardHeaders: true,
  legacyHeaders: false
});

const uploadLimiter = rateLimit({
  windowMs: RATE_LIMITS.UPLOAD.windowMs,
  max: RATE_LIMITS.UPLOAD.max,
  message: {
    error: {
      code: ERROR_CODES.FILE_UPLOAD_ERROR,
      message: 'Too many upload attempts, please try again later',
      timestamp: new Date().toISOString()
    }
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Apply rate limiting
// Apply auth rate limiting only to login/register endpoints, not logout
router.use('/auth/login', authLimiter);
router.use('/auth/register', authLimiter);
router.use('/auth/saml/login', authLimiter);
router.use('/materials/upload', uploadLimiter);
router.use('/', apiLimiter);

// Health check endpoint
router.get('/health', (req, res) => {
  res.status(HTTP_STATUS.OK).json({
    status: 'healthy',
    service: 'TLEF-CREATE API',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Mount route controllers
router.use('/auth', authController);
// router.use('/folders', folderController);
// router.use('/materials', materialController);
// router.use('/quizzes', quizController);
// router.use('/objectives', objectiveController);
// router.use('/plans', planController);
// router.use('/questions', questionController);
// router.use('/export', exportController);

// 404 handler for unknown API routes
router.use((req, res) => {
  return errorResponse(
    res,
    `Route ${req.originalUrl} not found`,
    ERROR_CODES.NOT_FOUND,
    HTTP_STATUS.NOT_FOUND
  );
});

// Global error handler
router.use((error, req, res, next) => {
  console.error('API Error:', error);

  // Mongoose validation error
  if (error.name === 'ValidationError') {
    const errors = Object.values(error.errors).map(err => ({
      field: err.path,
      message: err.message
    }));
    return errorResponse(
      res,
      'Validation failed',
      ERROR_CODES.VALIDATION_ERROR,
      HTTP_STATUS.BAD_REQUEST,
      errors
    );
  }

  // Mongoose cast error (invalid ObjectId)
  if (error.name === 'CastError') {
    return errorResponse(
      res,
      'Invalid ID format',
      ERROR_CODES.VALIDATION_ERROR,
      HTTP_STATUS.BAD_REQUEST
    );
  }

  // Duplicate key error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return errorResponse(
      res,
      `${field} already exists`,
      ERROR_CODES.DUPLICATE_RESOURCE,
      HTTP_STATUS.CONFLICT
    );
  }

  // Multer file upload errors
  if (error.code === 'LIMIT_FILE_SIZE') {
    return errorResponse(
      res,
      'File size too large',
      ERROR_CODES.FILE_UPLOAD_ERROR,
      HTTP_STATUS.BAD_REQUEST
    );
  }

  if (error.code === 'LIMIT_UNEXPECTED_FILE') {
    return errorResponse(
      res,
      'Unexpected file field',
      ERROR_CODES.FILE_UPLOAD_ERROR,
      HTTP_STATUS.BAD_REQUEST
    );
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return errorResponse(
      res,
      'Invalid token',
      ERROR_CODES.AUTH_ERROR,
      HTTP_STATUS.UNAUTHORIZED
    );
  }

  if (error.name === 'TokenExpiredError') {
    return errorResponse(
      res,
      'Token expired',
      ERROR_CODES.AUTH_ERROR,
      HTTP_STATUS.UNAUTHORIZED
    );
  }

  // Default server error
  return errorResponse(
    res,
    process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message,
    ERROR_CODES.DATABASE_ERROR,
    HTTP_STATUS.INTERNAL_SERVER_ERROR,
    process.env.NODE_ENV === 'development' ? { stack: error.stack } : null
  );
});

export default router;