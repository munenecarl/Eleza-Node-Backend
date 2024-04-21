import { createServer } from 'node:http';
import express from 'express';

const app = express();
const server = createServer(app);

app.get('/', (req, res) => {
    res.send('<h1>Hello World</h1>');
});

server.listen(3000, () => {
    console.log("Server running on port 3000")
});