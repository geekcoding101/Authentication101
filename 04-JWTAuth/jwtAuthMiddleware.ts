import { Request, Response, NextFunction } from 'express';
import { verifyToken } from './jwt';

export const jwtAuthMiddleware = (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header missing' });
        }

        const token = authHeader.split(' ')[1];
        const decodedUser = verifyToken(token);

        // Create a closure to pass the decoded user
        (req as any).getUser = () => decodedUser;

        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};
