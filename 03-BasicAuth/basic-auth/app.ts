import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import basicAuthMiddleware from './basicAuthMiddleware'; // Import the basicAuthMiddleware
import users from './usersData'; // Import the users data

const app = express();
const PORT = 3001;

app.use(bodyParser.json());

// User registration route
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if the user already exists
        if (users.some((user) => user.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash the password using bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save the user in the database (in this example, we're using an in-memory array)
        const newUser = { username, password: hashedPassword };
        users.push(newUser);

        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create the basicAuthMiddleware with the users array as an argument
const authMiddleware = basicAuthMiddleware(users);

// Use the authMiddleware to protect a route
app.get('/protected', authMiddleware, (req, res) => {
    res.json({ message: 'You have successfully accessed the protected route!' });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
