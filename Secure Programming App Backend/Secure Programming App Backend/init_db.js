const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./chatApp.db', (err) => {
  if (err) {
    console.error("Error opening database: ", err.message);
  } else {
    console.log("Database connected!");
  }
});

// Create tables
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT)");

  db.run("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(userId) REFERENCES users(id))");
});

db.close();
