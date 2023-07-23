import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';

const app = express();
const PORT = 3000;

app.use(bodyParser.json());

interface User {
  id: number;
  username: string;
  password: string;
}

let users: User[] = [];

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser: User = {
      id: users.length + 1,
      username,
      password: hashedPassword,
    };
    users.push(newUser);
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = users.find((user) => user.username === username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    res.json({ message: 'Login successful!' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

