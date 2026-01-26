const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const NodeCache = require('node-cache');
const app = express();

// ================== CONFIGURATION ==================
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

// Timezone configuration for Indian Standard Time
const INDIAN_TIMEZONE = 'Asia/Kolkata';

// ================== ENHANCED CACHING SYSTEM ==================
const userCache = new NodeCache({ stdTTL: 60, checkperiod: 120 });
const statsCache = new NodeCache({ stdTTL: 30, checkperiod: 60 });
const licenseCache = new NodeCache({ stdTTL: 300, checkperiod: 600 });
const serverKeyCache = new NodeCache({ stdTTL: 180, checkperiod: 360 });

// ================== RATE LIMITING ==================
const publicApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: { valid: false, error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5000,
    message: { error: 'Too many login attempts' }
});

// ================== DATABASE CONNECTION ==================
mongoose.connect('mongodb+srv://rsnetwork98:network.rs.99@cluster0.nasf6lg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0/advanceauth', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 20,
    minPoolSize: 5,
    maxIdleTimeMS: 30000,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
});

// ================== INDIAN TIMEZONE FUNCTIONS ==================
function getIndianDateTime() {
    return new Date().toLocaleString("en-US", { timeZone: INDIAN_TIMEZONE });
}

function formatIndianDate(date) {
    return date.toLocaleDateString('en-IN', {
        timeZone: INDIAN_TIMEZONE,
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// ================== EXISTING SCHEMAS (PRESERVED) ==================
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, index: true },
    email: { type: String, sparse: true },
    password: { type: String, required: true },
    serverKey: { type: String, required: true, index: true },
    lastLogin: { type: Date, default: Date.now },
    isBanned: { type: Boolean, default: false },
    banMessage: String,
    createdAt: { type: Date, default: Date.now },
    loginAttempts: { type: Number, default: 0 },
    lastAttempt: { type: Date, default: Date.now },
    ipAddress: String,
    location: String,
    deviceInfo: String,
    emailVerified: { type: Boolean, default: false },
    emailUpdatedAt: Date,
    twoFactorEnabled: { type: Boolean, default: false }
});

const serverKeySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    pluginEnabled: { type: Boolean, default: true },
    maxUsers: { type: Number, default: -1 },
    currentUsers: { type: Number, default: 0 },
    owner: String,
    description: String
});

const licenseSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    type: { type: String, enum: ['GLOBAL', 'SERVER_SPECIFIC'], default: 'GLOBAL' },
    maxServers: { type: Number, default: -1 },
    usedServers: [String],
    createdBy: String,
    createdAt: { type: Date, default: Date.now },
    validUntil: { type: Date, required: true },
    isActive: { type: Boolean, default: true },
    features: {
        unlimited_users: { type: Boolean, default: true },
        advanced_analytics: { type: Boolean, default: true },
        custom_branding: { type: Boolean, default: false },
        priority_support: { type: Boolean, default: false }
    }
});

const apiKeySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    name: String,
    serverKey: String,
    permissions: [String],
    rateLimit: { type: Number, default: 100 },
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
    isActive: { type: Boolean, default: true }
});

// ================== EXISTING INDEXES (PRESERVED) ==================
userSchema.index({ username: 1, serverKey: 1 }, { unique: true });
serverKeySchema.index({ key: 1, isActive: 1 });
licenseSchema.index({ key: 1, isActive: 1 });

const User = mongoose.model('User', userSchema);
const ServerKey = mongoose.model('ServerKey', serverKeySchema);
const License = mongoose.model('License', licenseSchema);
const ApiKey = mongoose.model('ApiKey', apiKeySchema);

// ================== EXISTING CACHE FUNCTIONS (PRESERVED) ==================
const LICENSE_KEYS_FILE = path.join(__dirname, 'licenseys.json');
let validLicenseKeys = new Map();
let lastCacheUpdate = 0;
const CACHE_TTL = 30000;

async function loadLicenseKeys() {
    try {
        const licenses = await License.find({ isActive: true }).lean();
        validLicenseKeys = new Map();

        licenses.forEach(license => {
            validLicenseKeys.set(license.key, {
                ...license,
                serverKey: license.type === 'SERVER_SPECIFIC' && license.usedServers.length > 0 ? license.usedServers[0] : null,
                used: license.usedServers.length > 0,
                usedBy: license.usedServers.length > 0 ? 'database' : null,
                usedAt: license.usedServers.length > 0 ? license.createdAt : null
            });
        });

        if (fs.existsSync(LICENSE_KEYS_FILE)) {
            const data = fs.readFileSync(LICENSE_KEYS_FILE, 'utf8');
            const licenseKeys = JSON.parse(data);

            licenseKeys.forEach(keyData => {
                if (!validLicenseKeys.has(keyData.key)) {
                    validLicenseKeys.set(keyData.key, keyData);
                }
            });
        }

        console.log(`Loaded ${validLicenseKeys.size} license keys from database and JSON`);

        if (validLicenseKeys.size === 0) {
            await createSampleLicenses();
        }
    } catch (error) {
        console.error('Error loading license keys:', error);
        validLicenseKeys = new Map();
        await createSampleLicenses();
    }
}

async function createSampleLicenses() {
    try {
        const sampleLicenses = [
            {
                key: "GLOBAL-2025-ABC123DEF456",
                type: "GLOBAL",
                maxServers: -1,
                createdBy: "system",
                validUntil: new Date("2025-12-31T23:59:59.000Z"),
                features: {
                    unlimited_users: true,
                    advanced_analytics: true,
                    custom_branding: true,
                    priority_support: true
                }
            },
            {
                key: "PREMIUM-2025-XYZ789GHI012",
                type: "GLOBAL",
                maxServers: 5,
                createdBy: "admin",
                validUntil: new Date("2026-01-15T23:59:59.000Z"),
                features: {
                    unlimited_users: true,
                    advanced_analytics: true,
                    custom_branding: false,
                    priority_support: true
                }
            },
            {
                key: "UNIVERSAL-DEMO-JKL345MNO678",
                type: "GLOBAL",
                maxServers: -1,
                createdBy: "system",
                validUntil: new Date("2026-06-30T23:59:59.000Z")
            }
        ];

        for (const licenseData of sampleLicenses) {
            const existingLicense = await License.findOne({ key: licenseData.key });
            if (!existingLicense) {
                const license = new License(licenseData);
                await license.save();
                console.log(`Created sample license: ${licenseData.key}`);
            }
        }

        await loadLicenseKeys();
    } catch (error) {
        console.error('Error creating sample licenses:', error);
    }
}

async function updateServerKeyCache() {
    try {
        const now = Date.now();
        if (now - lastCacheUpdate < CACHE_TTL) {
            return;
        }

        const serverKeys = await ServerKey.find({ isActive: true }).lean();
        serverKeyCache.flushAll();

        serverKeys.forEach(key => {
            serverKeyCache.set(key.key, key);
        });

        lastCacheUpdate = now;
    } catch (error) {
        console.error('Error updating server key cache:', error);
    }
}

async function isPluginEnabled(serverKey) {
    try {
        await updateServerKeyCache();

        const serverKeyData = serverKeyCache.get(serverKey);
        if (!serverKeyData || !serverKeyData.isActive) {
            return false;
        }

        const validLicenses = Array.from(validLicenseKeys.values()).filter(license => {
            if (!license.isActive || new Date(license.validUntil) < new Date()) {
                return false;
            }

            if (license.type === 'GLOBAL' || !license.serverKey) {
                if (license.maxServers && license.maxServers > 0 && license.usedServers) {
                    return license.usedServers.length < license.maxServers;
                }
                return true;
            }

            if (license.serverKey === serverKey || (license.usedServers && license.usedServers.includes(serverKey))) {
                return true;
            }

            return false;
        });

        return validLicenses.length > 0 && (serverKeyData.pluginEnabled !== false);
    } catch (error) {
        console.error('Error checking plugin status:', error);
        return false;
    }
}

// ================== EXISTING MIDDLEWARE (PRESERVED) ==================
const checkServerKey = async (req, res, next) => {
    try {
        const serverKey = req.body?.serverKey || req.query.serverKey || req.headers['server-key'];

        if (!serverKey) {
            return res.status(401).json({
                error: 'Server key required',
                code: 'NO_SERVER_KEY'
            });
        }

        await updateServerKeyCache();

        let validKey = serverKeyCache.get(serverKey);

        if (!validKey) {
            try {
                const newServerKey = new ServerKey({
                    key: serverKey,
                    name: `Auto-generated Server (${serverKey.substring(0, 8)}...)`,
                    isActive: true,
                    pluginEnabled: true,
                    owner: 'auto-generated',
                    description: 'Automatically created server key'
                });

                await newServerKey.save();
                await updateServerKeyCache();
                validKey = serverKeyCache.get(serverKey);

                console.log(`Auto-created server key: ${serverKey}`);
            } catch (error) {
                if (error.code !== 11000) {
                    console.error('Error auto-creating server key:', error);
                }
            }
        }

        if (!validKey || !validKey.isActive) {
            return res.status(401).json({
                error: 'Invalid server key',
                code: 'INVALID_SERVER_KEY'
            });
        }

        const pluginEnabled = await isPluginEnabled(serverKey);
        if (!pluginEnabled) {
            return res.status(403).json({
                error: 'Plugin disabled - No valid license key found',
                code: 'PLUGIN_DISABLED'
            });
        }

        req.serverKeyData = validKey;
        req.serverKey = serverKey;
        return next();

    } catch (error) {
        console.error('Server key validation error:', error);
        res.status(500).json({
            error: 'Server key validation failed',
            code: 'VALIDATION_ERROR'
        });
    }
};

// ================== NEW EMAIL FUNCTIONS (ADDED) ==================
async function sendEmail(to, subject, html) {
    try {
        const response = await axios.post('https://nodemailer-five-sigma.vercel.app/send-email', {
            to,
            subject,
            html
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        return { success: true, message: 'Email sent successfully' };
    } catch (error) {
        console.error('Email sending error:', error.message);
        return { success: false, error: error.message };
    }
}

const otpStore = new Map();
const OTP_EXPIRY = 10 * 60 * 1000;

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// ================== NEW PUBLIC API ROUTE (ADDED) ==================
app.get('/api/dataapikey/query', publicApiLimiter, async (req, res) => {
    try {
        const { tag, password, serverKey, apikey } = req.query;

        console.log(`Public API request: tag=${tag}, serverKey=${serverKey}`);

        if (!tag || !password) {
            return res.json({
                valid: false,
                error: 'Tag and password are required',
                timestamp: getIndianDateTime()
            });
        }

        let query = { username: tag };

        if (apikey) {
            const apiKeyData = await ApiKey.findOne({
                key: apikey,
                isActive: true,
                expiresAt: { $gt: new Date() }
            });

            if (!apiKeyData) {
                return res.json({
                    valid: false,
                    error: 'Invalid or expired API key',
                    timestamp: getIndianDateTime()
                });
            }

            if (serverKey) {
                query.serverKey = serverKey;
            }
        } else if (serverKey) {
            query.serverKey = serverKey;
        }
        const test = await bcrypt.compare("12346785", "$2b$12$0/znxFXP2m1SeVoPEYaCy.oBmzayg9Pt5hCx2RP2kNDDjqPA7kwH.");
        console.log("MANUAL TEST:", test);


        const user = await User.findOne(query).select('username password isBanned email').lean();

        if (!user) {
            return res.json({
                valid: false,
                error: 'User not found',
                exists: false,
                timestamp: getIndianDateTime(),
                indianTime: formatIndianDate(new Date())
            });
        }

        if (user.isBanned) {
            return res.json({
                valid: false,
                error: 'User is banned',
                banned: true,
                exists: true,
                timestamp: getIndianDateTime()
            });
        }

        const isValid = await bcrypt.compare(password, user.password);

        res.json({
            valid: isValid,
            exists: true,
            username: user.username,
            email: user.email || null,
            isBanned: user.isBanned,
            timestamp: getIndianDateTime(),
            indianTime: formatIndianDate(new Date()),
            serverTime: new Date().toLocaleString('en-IN', { timeZone: INDIAN_TIMEZONE })
        });
        console.log("Input password:", password);
        console.log("DB password:", user.password);


    } catch (error) {
        console.error('Public API error:', error);
        res.status(500).json({
            valid: false,
            error: 'Server error',
            message: error.message
        });
    }
});

// Add these routes after the existing admin routes

// ================== API KEY MANAGEMENT ROUTES ==================

// Get all API keys for current server
app.get('/api/admin/apiKeys', checkServerKey, async (req, res) => {
    try {
        const serverKey = req.serverKey;

        const apiKeys = await ApiKey.find({
            serverKey,
            isActive: true
        }).sort({ createdAt: -1 }).lean();

        res.json(apiKeys);
    } catch (error) {
        console.error('API keys fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch API keys' });
    }
});

// Delete API key
app.delete('/api/admin/apiKeys/:key', checkServerKey, async (req, res) => {
    try {
        const { key } = req.params;
        const serverKey = req.serverKey;

        const apiKey = await ApiKey.findOne({ key, serverKey });

        if (!apiKey) {
            return res.status(404).json({ error: 'API key not found' });
        }

        // Soft delete by setting isActive to false
        await ApiKey.updateOne({ key }, { isActive: false });

        res.json({
            success: true,
            message: 'API key deleted successfully'
        });
    } catch (error) {
        console.error('API key deletion error:', error);
        res.status(500).json({ error: 'Failed to delete API key' });
    }
});

// Get specific API key details
app.get('/api/admin/apiKeys/:key', checkServerKey, async (req, res) => {
    try {
        const { key } = req.params;
        const serverKey = req.serverKey;

        const apiKey = await ApiKey.findOne({
            key,
            serverKey,
            isActive: true
        }).lean();

        if (!apiKey) {
            return res.status(404).json({ error: 'API key not found' });
        }

        res.json(apiKey);
    } catch (error) {
        console.error('API key fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch API key' });
    }
});

// ================== NEW EMAIL MANAGEMENT ROUTES (ADDED) ==================
app.post('/api/setmail', async (req, res) => {
    try {
        const { username, email, serverKey } = req.body;

        if (!username || !email || !serverKey) {
            return res.status(400).json({
                success: false,
                error: 'Username, email, and serverKey are required'
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid email format'
            });
        }

        const user = await User.findOne({ username, serverKey });
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        const existingUser = await User.findOne({
            email,
            serverKey,
            username: { $ne: username }
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                error: 'Email already registered to another user'
            });
        }

        user.email = email;
        user.emailVerified = false;
        user.emailUpdatedAt = getIndianDateTime();
        await user.save();

        userCache.del(`${serverKey}_${username}`);

        res.json({
            success: true,
            message: 'Email updated successfully',
            username,
            email,
            updatedAt: getIndianDateTime(),
            indianDate: formatIndianDate(new Date())
        });

    } catch (error) {
        console.error('Setmail error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update email'
        });
    }
});

app.post('/api/changePassword/requestOTP', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                error: 'Email is required'
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'Email not registered'
            });
        }

        const otp = generateOTP();

        otpStore.set(email, {
            otp,
            expires: Date.now() + OTP_EXPIRY,
            attempts: 0,
            username: user.username
        });

        const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #1a1a1a; color: #ffffff; padding: 30px; border-radius: 10px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #6366f1; margin: 0;">🔐 AdvanceAuth</h1>
                    <p style="color: #94a3b8; margin: 5px 0;">Password Reset Request</p>
                </div>
                
                <div style="background: #2d2d2d; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <p style="margin: 10px 0;">Hello <strong>${user.username}</strong>,</p>
                    <p style="margin: 10px 0;">You requested to reset your password. Use the OTP below:</p>
                    
                    <div style="background: #6366f1; color: white; padding: 20px; text-align: center; font-size: 32px; letter-spacing: 10px; margin: 20px 0; border-radius: 8px; font-weight: bold;">
                        ${otp}
                    </div>
                    
                    <p style="margin: 10px 0; color: #94a3b8; font-size: 14px;">
                        This OTP is valid for 10 minutes. Do not share it with anyone.
                    </p>
                </div>
                
                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #374151;">
                    <p style="color: #94a3b8; font-size: 12px; margin: 5px 0;">
                        If you didn't request this, please ignore this email.
                    </p>
                    <p style="color: #94a3b8; font-size: 12px; margin: 5px 0;">
                        Need help? Join our Discord: <a href="https://discord.zenuxs.in" style="color: #6366f1;">discord.zenuxs.in</a>
                    </p>
                </div>
            </div>
        `;

        const emailResult = await sendEmail(email, 'Password Reset OTP - AdvanceAuth', emailHtml);

        if (!emailResult.success) {
            return res.status(500).json({
                success: false,
                error: 'Failed to send OTP email'
            });
        }

        res.json({
            success: true,
            message: 'OTP sent to email',
            expiresIn: '10 minutes',
            email: email.substring(0, 3) + '***' + email.substring(email.indexOf('@'))
        });

    } catch (error) {
        console.error('OTP request error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to process OTP request'
        });
    }
});

app.post('/api/changePassword/verifyOTP', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        if (!email || !otp || !newPassword) {
            return res.status(400).json({
                success: false,
                error: 'Email, OTP, and new password are required'
            });
        }

        const otpData = otpStore.get(email);
        if (!otpData) {
            return res.status(400).json({
                success: false,
                error: 'OTP not found or expired'
            });
        }

        if (Date.now() > otpData.expires) {
            otpStore.delete(email);
            return res.status(400).json({
                success: false,
                error: 'OTP expired'
            });
        }

        if (otpData.attempts >= 3) {
            otpStore.delete(email);
            return res.status(400).json({
                success: false,
                error: 'Too many OTP attempts'
            });
        }

        if (otpData.otp !== otp) {
            otpData.attempts++;
            otpStore.set(email, otpData);
            return res.status(400).json({
                success: false,
                error: 'Invalid OTP'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        await User.updateOne({ email }, {
            password: hashedPassword,
            loginAttempts: 0
        });

        otpStore.delete(email);

        const user = await User.findOne({ email });
        if (user) {
            userCache.del(`${user.serverKey}_${user.username}`);
        }

        res.json({
            success: true,
            message: 'Password changed successfully',
            changedAt: getIndianDateTime(),
            indianDate: formatIndianDate(new Date()),
            username: otpData.username
        });

    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to change password'
        });
    }
});

// ================== EXISTING ROUTES (PRESERVED EXACTLY AS BEFORE) ==================
app.post('/api/checkUser', checkServerKey, async (req, res) => {
    try {
        const { username } = req.body;
        const serverKey = req.serverKey;

        const cacheKey = `${serverKey}_${username}`;
        const cached = userCache.get(cacheKey);

        if (cached) {
            return res.json(cached);
        }

        const user = await User.findOne({ username, serverKey }).lean();
        const response = user ? {
            exists: true,
            action: 'login',
            message: 'User exists, please use /login'
        } : {
            exists: false,
            action: 'register',
            message: 'New user, please use /register'
        };

        userCache.set(cacheKey, response);
        res.json(response);

    } catch (error) {
        console.error('Check user error:', error);
        res.status(500).json({ error: 'Failed to check user' });
    }
});

app.post('/api/register', checkServerKey, async (req, res) => {
    try {
        const { username, email, password, licenseKey } = req.body;
        const serverKey = req.serverKey;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const existingUser = await User.findOne({ username, serverKey });
        if (existingUser) {
            return res.status(400).json({
                error: 'Username already taken for this server',
                code: 'USERNAME_TAKEN'
            });
        }

        if (licenseKey) {
            const keyData = validLicenseKeys.get(licenseKey);

            if (!keyData) {
                return res.status(400).json({ error: 'Invalid license key' });
            }

            if (!keyData.isActive || new Date(keyData.validUntil) < new Date()) {
                return res.status(400).json({ error: 'License key expired' });
            }

            if (keyData.type === 'SERVER_SPECIFIC' && keyData.serverKey && keyData.serverKey !== serverKey) {
                return res.status(400).json({ error: 'License key not valid for this server' });
            }

            if (keyData._id && keyData.type === 'GLOBAL') {
                await License.updateOne(
                    { _id: keyData._id },
                    { $addToSet: { usedServers: serverKey } }
                );
            }
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            serverKey,
            ipAddress: req.ip,
            location: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
            deviceInfo: req.headers['user-agent']
        });

        await newUser.save();

        await ServerKey.updateOne(
            { key: serverKey },
            { $inc: { currentUsers: 1 } }
        );

        res.json({
            message: 'User registered successfully',
            username: username
        });
    } catch (error) {
        console.error('Registration error:', error);
        if (error.code === 11000) {
            res.status(400).json({ error: 'Username already taken for this server' });
        } else {
            res.status(500).json({ error: 'Registration failed' });
        }
    }
});

app.post('/api/login', loginLimiter, checkServerKey, async (req, res) => {
    try {
        const { username, password } = req.body;
        const serverKey = req.serverKey;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const user = await User.findOne({ username, serverKey });

        if (!user) {
            return res.status(401).json({
                error: 'User not found, please use /register first',
                code: 'USER_NOT_FOUND'
            });
        }

        if (user.isBanned) {
            return res.status(403).json({
                error: user.banMessage || 'You are banned from this server',
                banned: true
            });
        }

        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

        if (user.lastAttempt > oneHourAgo && user.loginAttempts >= 5) {
            return res.status(429).json({
                error: 'Too many login attempts. Try again later.',
                code: 'RATE_LIMITED'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            await User.updateOne(
                { _id: user._id },
                {
                    $inc: { loginAttempts: 1 },
                    $set: { lastAttempt: now }
                }
            );

            return res.status(401).json({
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        await User.updateOne(
            { _id: user._id },
            {
                $set: {
                    loginAttempts: 0,
                    lastLogin: now,
                    ipAddress: req.ip,
                    location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
                }
            }
        );

        res.json({
            message: 'Login successful',
            username: username,
            lastLogin: user.lastLogin
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ================== EXISTING ADMIN ROUTES (PRESERVED) ==================
app.get('/api/admin/users', checkServerKey, async (req, res) => {
    try {
        const serverKey = req.serverKey;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;

        const users = await User.find({ serverKey })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        const totalUsers = await User.countDocuments({ serverKey });

        res.json({
            users,
            totalUsers,
            page,
            totalPages: Math.ceil(totalUsers / limit)
        });
    } catch (error) {
        console.error('Users fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/api/admin/deleteUser', checkServerKey, async (req, res) => {
    try {
        const { username } = req.body;
        const serverKey = req.serverKey;

        const result = await User.findOneAndDelete({ username, serverKey });
        if (result) {
            await ServerKey.updateOne(
                { key: serverKey },
                { $inc: { currentUsers: -1 } }
            );
        }

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.post('/api/admin/changePassword', checkServerKey, async (req, res) => {
    try {
        const { username, newPassword } = req.body;
        const serverKey = req.serverKey;

        const hashedPassword = await bcrypt.hash(newPassword, 12);

        await User.findOneAndUpdate(
            { username, serverKey },
            { password: hashedPassword }
        );

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

app.post('/api/admin/banUser', checkServerKey, async (req, res) => {
    try {
        const { username, banMessage } = req.body;
        const serverKey = req.serverKey;

        await User.findOneAndUpdate(
            { username, serverKey },
            { isBanned: true, banMessage: banMessage || 'Banned by administrator' }
        );

        res.json({ message: 'User banned successfully' });
    } catch (error) {
        console.error('Ban user error:', error);
        res.status(500).json({ error: 'Failed to ban user' });
    }
});

app.post('/api/admin/unbanUser', checkServerKey, async (req, res) => {
    try {
        const { username } = req.body;
        const serverKey = req.serverKey;

        await User.findOneAndUpdate(
            { username, serverKey },
            { isBanned: false, banMessage: '' }
        );

        res.json({ message: 'User unbanned successfully' });
    } catch (error) {
        console.error('Unban user error:', error);
        res.status(500).json({ error: 'Failed to unban user' });
    }
});

app.post('/api/admin/serverKeys', async (req, res) => {
    try {
        const { key, name, maxUsers, owner, description } = req.body;

        if (!key || !name) {
            return res.status(400).json({ error: 'Key and name are required' });
        }

        const newServerKey = new ServerKey({
            key,
            name,
            maxUsers: maxUsers || -1,
            owner: owner || 'admin',
            description: description || '',
            isActive: true,
            pluginEnabled: true
        });

        await newServerKey.save();
        await updateServerKeyCache();

        res.json({ message: 'Server key created successfully', key: newServerKey });
    } catch (error) {
        console.error('Server key creation error:', error);
        if (error.code === 11000) {
            res.status(400).json({ error: 'Server key already exists' });
        } else {
            res.status(500).json({ error: 'Failed to create server key' });
        }
    }
});

app.get('/api/admin/serverKeys', async (req, res) => {
    try {
        const keys = await ServerKey.find().sort({ createdAt: -1 }).lean();
        res.json(keys);
    } catch (error) {
        console.error('Server keys fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch server keys' });
    }
});

app.delete('/api/admin/serverKeys/:key', async (req, res) => {
    try {
        const { key } = req.params;
        await ServerKey.findOneAndDelete({ key });
        await updateServerKeyCache();
        res.json({ message: 'Server key deleted successfully' });
    } catch (error) {
        console.error('Server key deletion error:', error);
        res.status(500).json({ error: 'Failed to delete server key' });
    }
});

app.get('/api/admin/licenses', checkServerKey, async (req, res) => {
    try {
        const licenses = await License.find().sort({ createdAt: -1 }).lean();
        res.json(licenses);
    } catch (error) {
        console.error('Licenses fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch licenses' });
    }
});

app.post('/api/admin/licenses', checkServerKey, async (req, res) => {
    try {
        const { key, type, maxServers, validUntil, createdBy, features } = req.body;

        const licenseKey = key || generateLicenseKey();

        const existingLicense = await License.findOne({ key: licenseKey });
        if (existingLicense) {
            return res.status(400).json({ error: 'License key already exists' });
        }

        const newLicense = new License({
            key: licenseKey,
            type: type || 'GLOBAL',
            maxServers: maxServers || -1,
            validUntil: new Date(validUntil),
            createdBy: createdBy || 'admin',
            features: features || {
                unlimited_users: true,
                advanced_analytics: true,
                custom_branding: false,
                priority_support: false
            }
        });

        await newLicense.save();
        await loadLicenseKeys();

        res.json({
            message: 'License created successfully',
            license: newLicense
        });
    } catch (error) {
        console.error('License creation error:', error);
        res.status(500).json({ error: 'Failed to create license' });
    }
});

app.delete('/api/admin/licenses/:key', checkServerKey, async (req, res) => {
    try {
        const { key } = req.params;
        await License.findOneAndDelete({ key });
        await loadLicenseKeys();
        res.json({ message: 'License deleted successfully' });
    } catch (error) {
        console.error('License deletion error:', error);
        res.status(500).json({ error: 'Failed to delete license' });
    }
});

// ================== EXISTING HELPER ROUTES (PRESERVED) ==================
app.get('/api/pluginStatus', checkServerKey, async (req, res) => {
    try {
        const serverKey = req.serverKey;
        const isEnabled = await isPluginEnabled(serverKey);

        const validLicenses = Array.from(validLicenseKeys.values()).filter(license => {
            if (!license.isActive || new Date(license.validUntil) < new Date()) return false;
            if (license.type === 'GLOBAL' || !license.serverKey) return true;
            return license.serverKey === serverKey || (license.usedServers && license.usedServers.includes(serverKey));
        });

        res.json({
            enabled: isEnabled,
            serverKey: serverKey,
            validLicenses: validLicenses.length,
            message: isEnabled ? 'Plugin is enabled' : 'Plugin disabled - No valid license found'
        });
    } catch (error) {
        console.error('Plugin status error:', error);
        res.status(500).json({ error: 'Failed to check plugin status' });
    }
});

app.get('/api/stats', checkServerKey, async (req, res) => {
    try {
        const serverKey = req.serverKey;

        const totalUsers = await User.countDocuments({ serverKey });

        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const loggedInToday = await User.countDocuments({
            serverKey,
            lastLogin: { $gte: today }
        });

        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        const registrationsLast30Days = await User.countDocuments({
            serverKey,
            createdAt: { $gte: thirtyDaysAgo }
        });

        const bannedUsers = await User.countDocuments({ serverKey, isBanned: true });
        const activeUsers = totalUsers - bannedUsers;

        const last24hData = await getActivityData(serverKey, 24, 'hour');
        const last7dData = await getActivityData(serverKey, 7, 'day');
        const last30dData = await getActivityData(serverKey, 30, 'day');
        const registrationData = await getRegistrationData(serverKey, 30);
        const loginHeatmap = await getLoginHeatmap(serverKey);
        const topCountries = await getTopCountries(serverKey);

        res.json({
            totalUsers,
            loggedInToday,
            registrationsLast30Days,
            bannedUsers,
            activeUsers,
            last24hData,
            last7dData,
            last30dData,
            registrationData,
            loginHeatmap,
            topCountries
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.post('/api/validateToken', async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.json({ valid: false, error: 'No token provided' });
        }

        await updateServerKeyCache();

        const validKey = serverKeyCache.get(token);
        const pluginEnabled = await isPluginEnabled(token);

        if (validKey && pluginEnabled) {
            res.json({
                valid: true,
                serverKey: validKey.name,
                pluginEnabled: true
            });
        } else {
            res.json({
                valid: validKey ? true : false,
                pluginEnabled: pluginEnabled,
                error: !validKey ? 'Invalid server key' : 'Plugin disabled - No valid license'
            });
        }
    } catch (error) {
        console.error('Token validation error:', error);
        res.status(500).json({ error: 'Token validation failed' });
    }
});

app.get('/api/system/info', async (req, res) => {
    try {
        const totalServers = await ServerKey.countDocuments({ isActive: true });
        const totalUsers = await User.countDocuments();
        const totalLicenses = await License.countDocuments({ isActive: true });
        const activeLicenses = await License.countDocuments({
            isActive: true,
            validUntil: { $gt: new Date() }
        });

        res.json({
            version: '2.0.0',
            totalServers,
            totalUsers,
            totalLicenses,
            activeLicenses,
            uptime: process.uptime(),
            nodeVersion: process.version,
            author: 'DEVELOPER.RS (Rishabh)',
            company: 'Zenuxs',
            website: 'https://rs.zenuxs.xyz'
        });
    } catch (error) {
        console.error('System info error:', error);
        res.status(500).json({ error: 'Failed to fetch system info' });
    }
});

// ================== EXISTING HELPER FUNCTIONS (PRESERVED) ==================
async function getActivityData(serverKey, periods, interval) {
    const data = [];
    const now = new Date();

    for (let i = periods - 1; i >= 0; i--) {
        const start = new Date(now);
        const end = new Date(now);

        if (interval === 'hour') {
            start.setHours(now.getHours() - i - 1);
            end.setHours(now.getHours() - i);
        } else if (interval === 'day') {
            start.setDate(now.getDate() - i - 1);
            end.setDate(now.getDate() - i);
            start.setHours(0, 0, 0, 0);
            end.setHours(23, 59, 59, 999);
        }

        const count = await User.countDocuments({
            serverKey,
            lastLogin: { $gte: start, $lte: end }
        });

        data.push({
            period: interval === 'hour'
                ? `${start.getHours()}:00`
                : start.toLocaleDateString(),
            count
        });
    }

    return data;
}

async function getRegistrationData(serverKey, days) {
    const data = [];
    const now = new Date();

    for (let i = days - 1; i >= 0; i--) {
        const start = new Date(now);
        const end = new Date(now);

        start.setDate(now.getDate() - i - 1);
        end.setDate(now.getDate() - i);
        start.setHours(0, 0, 0, 0);
        end.setHours(23, 59, 59, 999);

        const count = await User.countDocuments({
            serverKey,
            createdAt: { $gte: start, $lte: end }
        });

        data.push({
            period: start.toLocaleDateString(),
            count
        });
    }

    return data;
}

async function getLoginHeatmap(serverKey) {
    const heatmapData = [];
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

    for (let hour = 0; hour < 24; hour++) {
        for (let day = 0; day < 7; day++) {
            const count = await User.countDocuments({
                serverKey,
                lastLogin: {
                    $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
                },
                $expr: {
                    $and: [
                        { $eq: [{ $dayOfWeek: '$lastLogin' }, day + 1] },
                        { $eq: [{ $hour: '$lastLogin' }, hour] }
                    ]
                }
            });

            heatmapData.push({
                day: days[day],
                hour,
                count
            });
        }
    }

    return heatmapData;
}

async function getTopCountries(serverKey) {
    const users = await User.find({ serverKey, location: { $exists: true, $ne: '' } })
        .limit(1000)
        .lean();

    const countries = {};
    users.forEach(user => {
        if (user.location) {
            const country = user.location.includes('::1') ? 'Localhost' : 'Unknown';
            countries[country] = (countries[country] || 0) + 1;
        }
    });

    return Object.entries(countries)
        .map(([country, count]) => ({ country, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);
}

function generateLicenseKey() {
    const prefixes = ['GLOBAL', 'PREMIUM', 'STANDARD', 'TRIAL', 'ENTERPRISE'];
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const year = new Date().getFullYear();

    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = prefix + '-' + year + '-';

    for (let i = 0; i < 2; i++) {
        if (i > 0) result += '';
        for (let j = 0; j < 6; j++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        if (i < 1) result += '';
    }
    return result
}

// ================== NEW ENHANCED ANALYTICS (ADDED) ==================
app.get('/api/enhancedStats', checkServerKey, async (req, res) => {
    try {
        const serverKey = req.serverKey;
        const cacheKey = `enhanced_stats_${serverKey}`;

        const cached = statsCache.get(cacheKey);
        if (cached) {
            return res.json({ ...cached, cached: true });
        }

        const stats = await calculateEnhancedStats(serverKey);
        statsCache.set(cacheKey, stats);

        res.json({ ...stats, cached: false });

    } catch (error) {
        console.error('Enhanced stats error:', error);
        res.status(500).json({ error: 'Failed to fetch enhanced stats' });
    }
});

async function calculateEnhancedStats(serverKey) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const [
        totalUsers,
        activeToday,
        newRegistrations,
        bannedUsers,
        userList
    ] = await Promise.all([
        User.countDocuments({ serverKey }),
        User.countDocuments({
            serverKey,
            lastLogin: { $gte: today }
        }),
        User.countDocuments({
            serverKey,
            createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }),
        User.countDocuments({ serverKey, isBanned: true }),
        User.find({ serverKey }).select('lastLogin createdAt').lean()
    ]);

    const hourCounts = new Array(24).fill(0);
    userList.forEach(user => {
        if (user.lastLogin) {
            const hour = new Date(user.lastLogin).getHours();
            hourCounts[hour]++;
        }
    });

    const peakHour = hourCounts.indexOf(Math.max(...hourCounts));

    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const activeLast7Days = await User.countDocuments({
        serverKey,
        lastLogin: { $gte: sevenDaysAgo }
    });

    const retentionRate = totalUsers > 0 ? ((activeLast7Days / totalUsers) * 100).toFixed(2) : 0;

    return {
        totalUsers,
        activeToday,
        newRegistrations,
        bannedUsers,
        activeUsers: totalUsers - bannedUsers,
        peakLoginHour: peakHour,
        retentionRate: `${retentionRate}%`,
        activeLast7Days,
        timestamp: getIndianDateTime(),
        indianDate: formatIndianDate(new Date()),
        timezone: 'IST (UTC+5:30)'
    };
}

// ================== NEW API KEY MANAGEMENT (ADDED) ==================
app.post('/api/admin/generateApiKey', checkServerKey, async (req, res) => {
    try {
        const { name, permissions = ['public_query'], rateLimit = 100, expiresInDays = 30 } = req.body;
        const serverKey = req.serverKey;

        const apiKey = require('crypto').randomBytes(32).toString('hex');

        const newApiKey = new ApiKey({
            key: apiKey,
            name: name || `API Key ${new Date().toLocaleDateString('en-IN')}`,
            serverKey,
            permissions,
            rateLimit,
            expiresAt: new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
        });

        await newApiKey.save();

        res.json({
            success: true,
            apiKey,
            name: newApiKey.name,
            expiresAt: newApiKey.expiresAt,
            permissions: newApiKey.permissions,
            rateLimit: newApiKey.rateLimit
        });

    } catch (error) {
        console.error('API key generation error:', error);
        res.status(500).json({ error: 'Failed to generate API key' });
    }
});

// ================== INITIALIZATION FUNCTIONS (PRESERVED) ==================
async function initializeServerKeys() {
    try {
        const defaultKey = await ServerKey.findOne({ key: 'c126434b-eaf2-439a-a759-ca7600a7e146' });

        if (!defaultKey) {
            const serverKey = new ServerKey({
                key: 'c126434b-eaf2-439a-a759-ca7600a7e146',
                name: 'Default Server Key',
                isActive: true,
                pluginEnabled: true,
                owner: 'Zenuxs',
                description: 'Default server key for AdvanceAuth'
            });
            await serverKey.save();
            console.log('Default server key created');
        }

        await updateServerKeyCache();
        console.log('Server keys initialized successfully');
    } catch (error) {
        console.error('Failed to initialize server keys:', error);
    }
}

async function initializeApp() {
    try {
        console.log('Initializing AdvanceAuth API...');

        await loadLicenseKeys();
        await initializeServerKeys();

        const PORT = process.env.PORT || 3000;

        app.listen(PORT, () => {
            console.log(`╔══════════════════════════════════════════╗`);
            console.log(`║           AdvanceAuth API v2.0.0         ║`);
            console.log(`║       by DEVELOPER.RS (Rishabh)          ║`);
            console.log(`║          Zenuxs Plugins Network          ║`);
            console.log(`║       https://rs.zenuxs.xyz              ║`);
            console.log(`║                                          ║`);
            console.log(`║   Server running on port ${PORT}         ║`);
            console.log(`║   Features: Multi-server licenses        ║`);
            console.log(`║   Database: MongoDB Atlas                ║`);
            console.log(`║   Status: /api/pluginStatus              ║`);
            console.log(`║   Admin: /admin                          ║`);
            console.log(`╚══════════════════════════════════════════╝`);
        });
    } catch (error) {
        console.error('Failed to initialize application:', error);
        process.exit(1);
    }
}

// ================== STATIC FILES AND ROUTES (PRESERVED) ==================
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use('/plugins', express.static(path.join(__dirname, 'plugins')));
app.use(express.static("public"));

app.get('/advancedAuth/dash', (req, res) => {
    res.sendFile(path.join(__dirname, "public/dash.html"));
});

app.get("/advancedAuth/e-dash", (req, res) => {
    res.sendFile(path.join(__dirname, "public/admin.html"));
});

app.get("/team", (req, res) => {
    res.sendFile(path.join(__dirname, "public/team.html"));
});

app.get("/about", (req, res) => {
    res.sendFile(path.join(__dirname, "public/about.html"));
});

app.get('/advancedAuth/', (req, res) => {
    res.sendFile(path.join(__dirname, "public/advanceAuth.html"));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, "public/index.html"));
});

app.get('/advancedAuth/dash/:token', (req, res) => {
    res.sendFile(path.join(__dirname, "public/dash.html"));
});

// ================== EXISTING HEALTH AND ERROR HANDLERS (PRESERVED) ==================
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        author: 'DEVELOPER.RS',
        company: 'Zenuxs'
    });
});

app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        message: 'The requested API endpoint does not exist',
        version: '2.0.0'
    });
});

app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        error: 'Internal server error',
        message: 'An unexpected error occurred'
    });
});

// ================== GRACEFUL SHUTDOWN (PRESERVED) ==================
process.on('SIGINT', async () => {
    console.log('Shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('Shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});

// ================== START APPLICATION ==================
initializeApp();