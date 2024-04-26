import { createServer } from 'node:http';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Server } from 'socket.io';
import sqlite3 from 'better-sqlite3';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

// Open the database file
const db = new sqlite3('chat.db');

// Create our 'messages' table (you can ignore the 'client_offset' column for now)
//TODO: add username/ID record
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clientOffset TEXT,
    content TEXT,
    username TEXT,
    FOREIGN KEY (username) REFERENCES users (username)
  );
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  );
`);

// Create an index on the username column
db.exec('CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);');
db.exec('CREATE INDEX IF NOT EXISTS idx_messages_username ON messages (username);');

const app = express();
const server = createServer(app);
const io = new Server(server);

const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(express.json());
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

// Move the hashing operation to a separate function
const hashPassword = async (password) => {
  console.time('bcrypt.hash');
  const hashedPassword = await bcrypt.hash(password, 10);
  console.timeEnd('bcrypt.hash');
  return hashedPassword;
};

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    const result = stmt.run(username, hashedPassword);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    const token = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_SECRET);
    res.status(201).send({ token });
  } catch (error) {
    console.error('Error in /signup route:', error);
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      res.status(400).send('Username already taken');
    } else {
      res.status(500).send('Server error');
    }
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Fetch user from your database based on username
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    return res.status(404).send('User not found');
  }

  const validPassword = await bcrypt.compare(password, user.password);

  if (!validPassword) {
    return res.status(400).send('Invalid username or password');
  }

  const token = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_SECRET);
  res.status(201).send({ token });
});

app.post('/logout', async (req, res) => {
  res.status(200).send('Logged out successfully')
});

// middleware function to authenticate WebSocket connections
const authenticateWebSocket = (socket, next) => {
  if (socket.handshake.query && socket.handshake.query.token) {
    jwt.verify(socket.handshake.query.token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        console.error('WebSocket authentication error:', err);
        return next(new Error('Authentication error'));
      }
      socket.decoded = decoded;
      next();
    });
  } else {
    next(new Error('Authentication token not provided'));
  }
};

// Apply the authentication middleware
io.use(authenticateWebSocket);

io.on('connection', async (socket) => {
  console.log('User connected:', socket.decoded);

  socket.on('chat message', async (data) => {
  const message = data.message;
  const clientOffset = data.clientOffset;
  const username = data.username;
  console.log('here is the username sent from the client', username, ' the message from the clienr ', message, ' and the clientOffset is ', clientOffset);

  try {
    // Prepare the SQL statement
    const stmt = db.prepare('INSERT INTO messages (content, clientOffset, username) VALUES (?, ?, ?)');
    // Execute the statement
    const info = stmt.run(message, clientOffset, username);

    if (info.changes > 0) {
      // Message was inserted successfully
      const lastInsertedId = info.lastInsertRowid;
      console.log('Received message:', message, 'Client offset:', clientOffset, 'Username:', username);
      console.log('Inserted message with ID:', lastInsertedId);

      // Include the offset with the message
      io.emit('chat message', { 'message': message, 'lastInsertedId': lastInsertedId, 'username': username });
      console.log('here is the message sent to the user ', message, 'its lastInsertedId ', lastInsertedId, 'and username', username);
    } else {
      // Message insertion failed
      console.error('Error inserting message:', message, 'Client offset:', clientOffset, 'username:', username);
    }
  } catch (e) {
    if (e.errno === 19) {
      // TODO: Notify the user that the message had already been sent
      console.log('Message already sent:', message, 'Client offset:', clientOffset, 'username', username);
    } else {
      // Just let the client try and send the message again
      console.error('Error inserting message:', e);
    }
  }
});

  socket.on('disconnect', () => {
    console.log('User disconnected');
  });

  if (!socket.recovered) {
    // If the connection state recovery was not successful
    try {
      const stmt = db.prepare('SELECT id, content FROM messages WHERE id > ?');
      const serverOffset = socket.handshake.auth.serverOffset || 0;
      for (const row of stmt.iterate([serverOffset])) {
        socket.emit('chat message', row.content, row.id);
      }
    } catch (e) {
      console.error('Error retrieving previous messages:', e);
    }
  }
});

server.listen(3000, () => {
  console.log('Server running on port 3000');
});