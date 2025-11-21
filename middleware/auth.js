const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token tidak ditemukan. Silakan login terlebih dahulu.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedPayload) => {
    if (err) {
      console.error('JWT Verify Error:', err.message);
      return res.status(403).json({ error: 'Token tidak valid atau kedaluwarsa' });
    }

    req.user = decodedPayload.user;
    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Tidak terautentikasi' });
    }

    if (req.user.role === role) {
      next(); 
    } else {
      return res.status(403).json({ error: 'Akses ditolak: peran tidak memiliki izin' });
    }
  };
}

module.exports = {
  authenticateToken,
  authorizeRole
};