import { Request, Response, NextFunction } from 'express';
import { Buffer } from 'buffer';
import bcrypt from 'bcryptjs';

interface User {
    username: string;
    password: string;
}

const basicAuthMiddleware = (users: User[]) => async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header missing' });
        }

        const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf-8');
        const [username, password] = credentials.split(':');

        const user = users.find((user) => user.username === username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid username' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        next();
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
};

export default basicAuthMiddleware;
