require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');
const { authenticateToken, authorizeRole } = require('./middleware/auth');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3300;
const JWT_SECRET = process.env.JWT_SECRET;


app.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username dan password wajib diisi' });

    const hashed = await bcrypt.hash(password, 10);

    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    const params = [username.toLowerCase(), hashed, 'user'];

    db.run(sql, params, function (err) {
      if (err) {
        if (err.message.includes('UNIQUE'))
          return res.status(400).json({ error: 'Username sudah digunakan' });
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ message: 'Registrasi berhasil', userId: this.lastID });
    });
  } catch (err) {
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

app.post('/auth/register-admin', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username dan password wajib diisi' });

    const hashed = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    const params = [username.toLowerCase(), hashed, 'admin'];

    db.run(sql, params, function (err) {
      if (err) {
        if (err.message.includes('UNIQUE'))
          return res.status(409).json({ error: 'Username admin sudah ada' });
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ message: 'Admin berhasil dibuat', userId: this.lastID });
    });
  } catch (err) {
    res.status(500).json({ error: 'Terjadi kesalahan server' });
  }
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username dan password wajib diisi' });

  db.get('SELECT * FROM users WHERE username = ?', [username.toLowerCase()], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'User tidak ditemukan' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Password salah' });

    const payload = {
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    };

    jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) return res.status(500).json({ error: 'Gagal membuat token' });
      res.json({ message: 'Login berhasil', token });
    });
  });
});

app.get('/movies', (req, res) => {
  db.all('SELECT * FROM movies', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/movies', authenticateToken, (req, res) => {
  const { title, director, year } = req.body;
  db.run(
    'INSERT INTO movies (title, director, year) VALUES (?, ?, ?)',
    [title, director, year],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      console.log(`Film ditambahkan oleh user: ${req.user.username}`);
      res.status(201).json({ id: this.lastID, title, director, year });
    }
  );
});

app.put('/movies/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  const { title, director, year } = req.body;
  db.run(
    'UPDATE movies SET title=?, director=?, year=? WHERE id=?',
    [title, director, year, req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      console.log(`Film diperbarui oleh admin: ${req.user.username}`);
      res.json({ message: 'Film berhasil diperbarui' });
    }
  );
});

app.delete('/movies/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  db.run('DELETE FROM movies WHERE id=?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
      console.log(`Film dihapus oleh admin: ${req.user.username}`);
    res.json({ message: 'Film berhasil dihapus' });
  });
});

app.get('/directors', (req, res) => {
  db.all('SELECT * FROM directors', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/directors', authenticateToken, (req, res) => {
  try {
    const { name, birthYear } = req.body;
    
    // Validasi input
    if (!name || name.trim() === '') {
      return res.status(400).json({ error: 'Nama sutradara wajib diisi' });
    }
    
    // Validasi dan konversi birthYear
    const birthYearNum = parseInt(birthYear);
    if (!birthYear || isNaN(birthYearNum)) {
      return res.status(400).json({ error: 'Tahun lahir harus berupa angka valid' });
    }
    
    // Validasi range tahun lahir masuk akal (misal: 1900-2024)
    if (birthYearNum < 1900 || birthYearNum > 2024) {
      return res.status(400).json({ error: 'Tahun lahir harus antara 1900-2024' });
    }

    // Insert ke database dengan nilai yang sudah divalidasi
    db.run(
      'INSERT INTO directors (name, birthYear) VALUES (?, ?)',
      [name.trim(), birthYearNum],
      function (err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Gagal menambahkan data sutradara' });
        }

        console.log(`Sutradara ditambahkan oleh user: ${req.user.username}`);
        res.status(201).json({
          id: this.lastID,
          name: name.trim(),
          birthYear: birthYearNum
        });
      }
    );
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Terjadi kesalahan internal server' });
  }
});

// update sutradara (perlu admin)
app.put('/directors/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  try {
    const { name, birthYear } = req.body;
    
    // Validasi input
    if (!name || name.trim() === '') {
      return res.status(400).json({ error: 'Nama sutradara wajib diisi' });
    }
    
    // Validasi dan konversi birthYear
    const birthYearNum = parseInt(birthYear);
    if (!birthYear || isNaN(birthYearNum)) {
      return res.status(400).json({ error: 'Tahun lahir harus berupa angka valid' });
    }
    
    if (birthYearNum < 1900 || birthYearNum > 2024) {
      return res.status(400).json({ error: 'Tahun lahir harus antara 1900-2024' });
    }

    db.run(
      'UPDATE directors SET name=?, birthYear=? WHERE id=?',
      [name.trim(), birthYearNum, req.params.id],
      function (err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Gagal memperbarui data sutradara' });
        }
        console.log(`Sutradara diperbarui oleh admin: ${req.user.username}`);
        res.json({ 
          message: 'Data sutradara berhasil diperbarui',
          data: { id: req.params.id, name: name.trim(), birthYear: birthYearNum }
        });
      }
    );
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Terjadi kesalahan internal server' });
  }
});

app.delete('/directors/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
  db.run('DELETE FROM directors WHERE id=?', [req.params.id], function (err) {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Gagal menghapus data sutradara' });
    }
    console.log(`Sutradara dihapus oleh admin: ${req.user.username}`);
    res.json({ message: 'Data sutradara berhasil dihapus' });
  });
});

app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});