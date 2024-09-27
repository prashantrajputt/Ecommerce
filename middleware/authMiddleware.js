import { config } from "dotenv";
import jwt from "jsonwebtoken";

config();
const JWT_SECRET='9b204e52ca893d0e2c37fe526bf3a48250763a6157220835defe04bc5a36c1be'

const auth = async (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')){
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();
    } catch (e) {
        console.error("Token verification error:", e.message);
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

export { auth };