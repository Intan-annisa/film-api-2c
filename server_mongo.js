require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/database');
const Movie = require('./models/Movie');
const Director = require('./models/Director');

const app = express();
const PORT = process.env.PORT || 3200;

// db connection
connectDB();

app.use(cors());
app.use(express.json());

// status
app.get('/status', (req, res) => {
  res.json({ ok: true, service: 'film-api' });
});

// movies CRUD
// GET all movies
app.get('/movies', async (req, res, next) => {
  try {
    const movies = await Movie.find({});
    res.json(movies);
  } catch (err) {
    next(err);
  }
});

// GET movie by ID
app.get('/movies/:id', async (req, res, next) => {
  try {
    const movie = await Movie.findById(req.params.id);
    if (!movie) return res.status(404).json({ error: 'Film tidak ditemukan' });
    res.json(movie);
  } catch (err) {
    if (err.kind === 'ObjectId')
      return res.status(400).json({ error: 'Format ID tidak valid' });
    next(err);
  }
});

// POST new movie
app.post('/movies', async (req, res, next) => {
  try {
    const { title, director, year } = req.body;
    if (!title || !director || !year)
      return res.status(400).json({ error: 'title, director, year wajib diisi' });

    const newMovie = new Movie({ title, director, year });
    const savedMovie = await newMovie.save();
    res.status(201).json(savedMovie);
  } catch (err) {
    if (err.name === 'ValidationError')
      return res.status(400).json({ error: err.message });
    next(err);
  }
});

// PUT update movie
app.put('/movies/:id', async (req, res, next) => {
  try {
    const { title, director, year } = req.body;
    const updatedMovie = await Movie.findByIdAndUpdate(
      req.params.id,
      { title, director, year },
      { new: true, runValidators: true }
    );
    if (!updatedMovie)
      return res.status(404).json({ error: 'Film tidak ditemukan' });
    res.json(updatedMovie);
  } catch (err) {
    if (err.kind === 'ObjectId')
      return res.status(400).json({ error: 'Format ID tidak valid' });
    next(err);
  }
});

// DELETE movie
app.delete('/movies/:id', async (req, res, next) => {
  try {
    const deletedMovie = await Movie.findByIdAndDelete(req.params.id);
    if (!deletedMovie)
      return res.status(404).json({ error: 'Film tidak ditemukan' });
    res.status(204).send();
  } catch (err) {
    if (err.kind === 'ObjectId')
      return res.status(400).json({ error: 'Format ID tidak valid' });
    next(err);
  }
});

// directors CRUD
// GET all directors
app.get('/directors', async (req, res, next) => {
  try {
    const directors = await Director.find({});
    res.json(directors);
  } catch (err) {
    next(err);
  }
});

// GET director by ID
app.get('/directors/:id', async (req, res, next) => {
  try {
    const director = await Director.findById(req.params.id);
    if (!director)
      return res.status(404).json({ error: 'Sutradara tidak ditemukan' });
    res.json(director);
  } catch (err) {
    if (err.kind === 'ObjectId')
      return res.status(400).json({ error: 'Format ID tidak valid' });
    next(err);
  }
});

// POST new director
app.post('/directors', async (req, res, next) => {
  try {
    const { name, birthYear } = req.body;
    if (!name || !birthYear)
      return res.status(400).json({ error: 'name dan birthYear wajib diisi' });

    const newDirector = new Director({ name, birthYear });
    const savedDirector = await newDirector.save();
    res.status(201).json(savedDirector);
  } catch (err) {
    if (err.name === 'ValidationError')
      return res.status(400).json({ error: err.message });
    next(err);
  }
});

// PUT update director
app.put('/directors/:id', async (req, res, next) => {
  try {
    const { name, birthYear } = req.body;
    const updatedDirector = await Director.findByIdAndUpdate(
      req.params.id,
      { name, birthYear },
      { new: true, runValidators: true }
    );
    if (!updatedDirector)
      return res.status(404).json({ error: 'Sutradara tidak ditemukan' });
    res.json(updatedDirector);
  } catch (err) {
    if (err.kind === 'ObjectId')
      return res.status(400).json({ error: 'Format ID tidak valid' });
    next(err);
  }
});

// DELETE director
app.delete('/directors/:id', async (req, res, next) => {
  try {
    const deletedDirector = await Director.findByIdAndDelete(req.params.id);
    if (!deletedDirector)
      return res.status(404).json({ error: 'Sutradara tidak ditemukan' });
    res.status(204).send();
  } catch (err) {
    if (err.kind === 'ObjectId')
      return res.status(400).json({ error: 'Format ID tidak valid' });
    next(err);
  }
});

// Fallback 404
app.use((req, res) => {
  res.status(404).json({ error: 'Rute tidak ditemukan' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

app.listen(PORT, () => {
  console.log(`Server aktif di http://localhost:${PORT}`);
});