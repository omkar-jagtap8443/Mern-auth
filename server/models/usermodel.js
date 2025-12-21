import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
    {
        name: { type: String, required: true, trim: true },
        email: { type: String, required: true, unique: true, lowercase: true, trim: true },
        password: { type: String, required: true },
        // Email verification
        isAccountverified: { type: Boolean, default: false },
        verifyotp: { type: String, default: '' },
        verifyotpExpireAt: { type: Number, default: 0 },
        // Password reset
        resetotp: { type: String, default: '' },
        resetotpExpireAt: { type: Number, default: 0 },
        // Refresh sessions for logout/rotation
        sessions: [
            {
                tokenHash: { type: String, required: true },
                userAgent: { type: String },
                ip: { type: String },
                createdAt: { type: Date, default: Date.now },
                expiresAt: { type: Date, required: true }
            }
        ]
    },
    { timestamps: true }
);

const userModel = mongoose.models.user || mongoose.model('user', userSchema);

export default userModel;