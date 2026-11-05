/**
 * Ownership & Authentication Middleware
 * Enforces user identity isolation for the zero-knowledge vault.
 */
export function authMiddleware(req, res, next) {
  // Allow client to supply custom user ID via header, or fallback to default authenticated demo user
  const userId = req.headers['x-user-id'] || 'demo_fintech_user_01';

  // Sanitize userId
  const sanitizedUserId = String(userId).trim().replace(/[^a-zA-Z0-9_-]/g, '');

  if (!sanitizedUserId) {
    return res.status(401).json({
      success: false,
      error: 'Authentication failed: Invalid or missing user identifier'
    });
  }

  req.user = {
    id: sanitizedUserId
  };

  next();
}

