import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";

const router = express.Router();
const JWT_SECRET='9b204e52ca893d0e2c37fe526bf3a48250763a6157220835defe04bc5a36c1be'
//ROUTE FOR REGISTER
router.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const newUser = new User({
            email,
            password: hashedPassword
        });

        const savedUser = await newUser.save();

        const token = jwt.sign({ id: savedUser._id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ token, msg: 'User registered successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

//ROUTE FOR LOGIN
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            const payload = {
                id: user._id,
                email: user.email
            };

            jwt.sign(
                payload,
                JWT_SECRET,
                { expiresIn: 3600 },
                (error, token) => {
                    if (error) throw error;

                    res.json({
                        token,
                        user: { id: user._id, email: user.email }
                    });
                }
            );
        } else {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

export { router as authRouter };