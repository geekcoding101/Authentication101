import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import users from './usersData';
import { jwtAuthMiddleware } from './jwtAuthMiddleware';
import { generateAccessToken, generateRefreshToken, verifyToken } from './jwt';

const app = express();
const PORT = 3001;

app.use(bodyParser.json());

// User registration route
app.post('/register', async (req: Request, res: Response) => {
    try {
        const { username, password } = req.body;

        // Check if the user already exists
        if (users.some((user) => user.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash the password using bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save the user
        const newUser = { username, password: hashedPassword };
        users.push(newUser);

        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/user/:username', (req: Request, res: Response) => {
  const { username } = req.params;
  const userIndex = users.findIndex(user => user.username === username);

  if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
  }

  users.splice(userIndex, 1);
  res.status(200).json({ message: `User ${username} deleted successfully` });
});

app.get('/users', (req: Request, res: Response) => {
  const usersWithoutPasswords = users.map(({ password, ...userWithoutPassword }) => userWithoutPassword);
  res.json(usersWithoutPasswords);
});


// User login route
app.post('/login', async (req: Request, res: Response) => {
    try {
        const { username, password } = req.body;
        const user = users.find((user) => user.username === username);

        if (!user) {
            return res.status(401).json({ error: 'Invalid username' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        const accessToken = generateAccessToken(username);
        const refreshToken = generateRefreshToken(username);
        res.json({ accessToken, refreshToken });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Refresh token route
app.post('/refresh', (req: Request, res: Response) => {
    const { refreshToken } = req.body;
    try {
        const decoded = verifyToken(refreshToken);
        if (decoded.type !== 'refresh') {
            return res.status(401).json({ error: 'Invalid refresh token' });
        }
        const newAccessToken = generateAccessToken(decoded.username);
        res.json({ accessToken: newAccessToken });
    } catch (error) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

// Protected route
app.get('/protected', jwtAuthMiddleware, (req: Request, res: Response) => {
  const user = (req as any).getUser();
  res.json({ message: 'Protected route accessed', user });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
