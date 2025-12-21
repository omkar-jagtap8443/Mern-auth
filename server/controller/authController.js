import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';
import sanitize from 'mongo-sanitize';
import transporter from '../config/nodemailer.js';
import { createAccessToken, createRefreshToken, verifyRefreshToken, hashToken, cookieOptions } from '../utils/tokens.js';
import { getClientInfo } from '../middleware/auth.js';



export const register = async (req, res) => {
    const body = sanitize(req.body);
    const { name, email, password } = body;
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: 'Missing details' });
    }

    try {
        const existing = await userModel.findOne({ email });
        if (existing) {
            return res.status(409).json({ success: false, message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        // Create initial refresh session
        const refresh = createRefreshToken(user._id.toString());
        const { userAgent, ip } = getClientInfo(req);
        user.sessions.push({
            tokenHash: hashToken(refresh),
            userAgent,
            ip,
            expiresAt: new Date(Date.now() + (1000 * 60 * 60 * 24 * 7))
        });
        await user.save();

        // Set refresh cookie and return access token
        res.cookie('refresh_token', refresh, cookieOptions());
        const access = createAccessToken(user._id.toString());

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to our platform',
            html: `<h2>Hello ${name}</h2><p>Your account was created successfully.</p>`
        };
        transporter.sendMail(mailOptions).catch(() => {});

        return res.status(201).json({ success: true, message: 'User registered successfully', accessToken: access });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

export const login = async (req, res) => {
    const body = sanitize(req.body);
    const { email, password } = body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Missing details' });
    }
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const refresh = createRefreshToken(user._id.toString());
        const { userAgent, ip } = getClientInfo(req);
        user.sessions.push({
            tokenHash: hashToken(refresh),
            userAgent,
            ip,
            expiresAt: new Date(Date.now() + (1000 * 60 * 60 * 24 * 7))
        });
        await user.save();

        res.cookie('refresh_token', refresh, cookieOptions());
        const access = createAccessToken(user._id.toString());
        return res.json({ success: true, message: 'Login successful', accessToken: access });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};



export const logout = async (req, res) => {
    try {
        const refresh = req.cookies?.refresh_token;
        if (refresh) {
            const payload = verifyRefreshToken(refresh);
            const user = await userModel.findById(payload.id);
            if (user) {
                const hashed = hashToken(refresh);
                user.sessions = user.sessions.filter((s) => s.tokenHash !== hashed);
                await user.save();
            }
        }
        res.clearCookie('refresh_token', cookieOptions());
        return res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        return res.status(200).json({ success: true, message: 'Logged out' });
    }
};

export const refresh = async (req, res) => {
    try {
        const token = req.cookies?.refresh_token;
        if (!token) {
            return res.status(401).json({ success: false, message: 'Missing refresh token' });
        }
        const payload = verifyRefreshToken(token);
        const user = await userModel.findById(payload.id);
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid refresh token' });
        }
        const hashed = hashToken(token);
        const session = user.sessions.find((s) => s.tokenHash === hashed);
        if (!session || session.expiresAt < new Date()) {
            return res.status(401).json({ success: false, message: 'Refresh session expired' });
        }
        // rotate refresh token
        const newRefresh = createRefreshToken(user._id.toString());
        session.tokenHash = hashToken(newRefresh);
        session.expiresAt = new Date(Date.now() + (1000 * 60 * 60 * 24 * 7));
        await user.save();
        res.cookie('refresh_token', newRefresh, cookieOptions());
        const access = createAccessToken(user._id.toString());
        return res.json({ success: true, accessToken: access });
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
    }
};

export const me = async (req, res) => {
    try {
        const user = await userModel.findById(req.user.id).select('name email isAccountverified');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        return res.json({ success: true, user });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

export const changePassword = async (req, res) => {
    try {
        const { currentPassword, newPassword } = sanitize(req.body);
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'Missing details' });
        }
        const user = await userModel.findById(req.user.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) return res.status(401).json({ success: false, message: 'Invalid current password' });
        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();
        return res.json({ success: true, message: 'Password updated' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

export const forgotPassword = async (req, res) => {
    try {
        const { email } = sanitize(req.body);
        if (!email) return res.status(400).json({ success: false, message: 'Email required' });
        const user = await userModel.findOne({ email });
        if (!user) return res.status(200).json({ success: true, message: 'If the email exists, a reset was sent' });
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.resetotp = otp;
        user.resetotpExpireAt = Date.now() + 15 * 60 * 1000; // 15 minutes
        await user.save();
        await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Password reset code',
            html: `<p>Your password reset code is <b>${otp}</b>. It expires in 15 minutes.</p>`
        });
        return res.json({ success: true, message: 'Reset code sent' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

export const resetPassword = async (req, res) => {
    try {
        const { email, otp, newPassword } = sanitize(req.body);
        if (!email || !otp || !newPassword) {
            return res.status(400).json({ success: false, message: 'Missing details' });
        }
        const user = await userModel.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (user.resetotp !== otp || user.resetotpExpireAt < Date.now()) {
            return res.status(400).json({ success: false, message: 'Invalid or expired reset code' });
        }
        user.password = await bcrypt.hash(newPassword, 12);
        user.resetotp = '';
        user.resetotpExpireAt = 0;
        await user.save();
        return res.json({ success: true, message: 'Password reset successful' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

