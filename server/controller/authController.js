import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';


export const register = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.json({ success: false, message: 'missing Details' })
    }

    try {

        const existinguser = await userModel.findOne({ email });
        if (existinguser) {
            return res.json({
                success: false, message: 'user already exists with this email '
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true });

    }
    catch (error) {
        res.json({ success: false, message: error.message })
    }

}

export const login = async (req, res) => {
    const {  email, password } = req.body;

    if ( !email || !password) {
        return res.json({ success: false, message: 'Missing Details' });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'Invalid email' });
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.json({ success: false, message: 'Invalid password' });
        }

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true ,message:'login successful' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};



export const logout = async (req,res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

        return res.json({ success: true, message: "Logged out successfully" });

    }
    catch (error) {
        res.json({ success: false, message: error.message });
    }
}

