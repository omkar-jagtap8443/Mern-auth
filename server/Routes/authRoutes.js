import express from 'express';
import { login, logout, register, refresh, me, changePassword, forgotPassword, resetPassword } from '../controller/authController.js';
import { requireAuth } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { registerSchema, loginSchema, forgotSchema, resetSchema, changePasswordSchema } from '../validators/auth.js';

const authRouter = express.Router();

authRouter.post('/register', validate(registerSchema), register);
authRouter.post('/login', validate(loginSchema), login);
authRouter.post('/logout', logout);
authRouter.post('/refresh', refresh);
authRouter.get('/me', requireAuth, me);
authRouter.post('/change-password', requireAuth, validate(changePasswordSchema), changePassword);
authRouter.post('/forgot-password', validate(forgotSchema), forgotPassword);
authRouter.post('/reset-password', validate(resetSchema), resetPassword);

export default authRouter;
