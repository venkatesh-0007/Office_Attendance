const dbHelpers = require('./db');

function authenticate(req, res, next) {
  let token = req.cookies?.session_token;

  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
      token = parts[1];
    }
  }

  if (token) {
    const session = dbHelpers.getSession(token);
    if (session) {
      req.user = {
        id: session.employee_id,
        name: session.name,
        email: session.email,
        role: session.role,
        department: session.department,
        employee_code: session.employee_code,
        token
      };
    }
  }

  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Administrator privileges required.' });
  }
  next();
}

module.exports = {
  authenticate,
  requireAuth,
  requireAdmin
};
