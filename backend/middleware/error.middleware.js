/**
 * Centralized Error Middleware
 */
export function errorMiddleware(err, req, res, next) {
  console.error('[Vault Error]', err);

  const statusCode = err.statusCode || (err.status ? err.status : 500);
  const message = err.message || 'An internal server error occurred in the vault service.';

  res.status(statusCode).json({
    success: false,
    error: message,
    code: err.code || 'VAULT_ERROR'
  });
}

