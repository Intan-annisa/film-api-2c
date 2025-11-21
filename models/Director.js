const mongoose = require('mongoose');

const directorSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  birthYear: { type: Number, required: true }
}, { timestamps: true });

module.exports = mongoose.model('Director', directorSchema);