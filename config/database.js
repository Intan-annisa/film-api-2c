require('dotenv').config();
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI);
    console.log(`✅ MongoDB Terhubung: ${conn.connection.host}`);
  } catch (error) {
    console.error(`❌ Error Koneksi DB: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
