import { z } from 'zod';

export const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Password must be at least 8 characters')
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Password must be at least 8 characters')
});

export const forgotSchema = z.object({
  email: z.string().email('Invalid email')
});

export const resetSchema = z.object({
  email: z.string().email('Invalid email'),
  otp: z.string().length(6, 'OTP must be 6 digits'),
  newPassword: z.string().min(8, 'Password must be at least 8 characters')
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(8, 'Invalid current password'),
  newPassword: z.string().min(8, 'Password must be at least 8 characters')
});
