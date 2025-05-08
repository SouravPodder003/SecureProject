const request = require('supertest');
const app = require('../server');
const sqlite3 = require('sqlite3').verbose();

let db;

beforeAll((done) => {
  db = new sqlite3.Database(':memory:');
  db.serialize(() => {
    db.run(`CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user'
    )`, done);
  });
});

afterAll(() => {
  db.close();
});

describe('Auth Routes', () => {
  it('should fail signup with invalid email', async () => {
    const res = await request(app)
      .post('/signup')
      .send({
        username: "testuser",
        email: "invalid-email",
        password: "password123"
      });
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toBe('Invalid email format');
  });

  it('should sign up successfully', async () => {
    const res = await request(app)
      .post('/signup')
      .send({
        username: "testuser",
        email: "test@example.com",
        password: "password123"
      });
    expect(res.statusCode).toBe(201);
    expect(res.body.token).toBeDefined();
  });

  it('should login successfully', async () => {
    const res = await request(app)
      .post('/signin')
      .send({
        email: "test@example.com",
        password: "password123"
      });
    expect(res.statusCode).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user).toHaveProperty('email', 'test@example.com');
  });
});
