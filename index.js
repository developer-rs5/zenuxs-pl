const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to MongoDB with optimized settings
mongoose.connect('mongodb+srv://rsnetwork98:network.rs.99@cluster0.nasf6lg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0/advanceauth', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
});

// User Schema
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
    deviceInfo: String
});

// Server Key Schema
const serverKeySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    pluginEnabled: { type: Boolean, default: true },
    maxUsers: { type: Number, default: -1 }, // -1 for unlimited
    currentUsers: { type: Number, default: 0 },
    owner: String,
    description: String
});

// License Schema  
const licenseSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    type: { type: String, enum: ['GLOBAL', 'SERVER_SPECIFIC'], default: 'GLOBAL' },
    maxServers: { type: Number, default: -1 }, // -1 for unlimited
    usedServers: [String], // Array of server keys using this license
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

// Add compound indexes for better performance
userSchema.index({ username: 1, serverKey: 1 }, { unique: true });
serverKeySchema.index({ key: 1, isActive: 1 });

const User = mongoose.model('User', userSchema);
const ServerKey = mongoose.model('ServerKey', serverKeySchema);
const License = mongoose.model('License', licenseSchema);

// JSON file path for backward compatibility
const LICENSE_KEYS_FILE = path.join(__dirname, 'licenseys.json');

// In-memory cache for better performance
let validLicenseKeys = new Map();
let serverKeyCache = new Map();
let lastCacheUpdate = 0;
const CACHE_TTL = 30000; // 30 seconds cache

// Load license keys from both JSON and Database
async function loadLicenseKeys() {
    try {
        // Load from database first
        const licenses = await License.find({ isActive: true }).lean();
        validLicenseKeys = new Map();
        
        licenses.forEach(license => {
            validLicenseKeys.set(license.key, {
                ...license,
                // Convert to old format for backward compatibility
                serverKey: license.type === 'SERVER_SPECIFIC' && license.usedServers.length > 0 ? license.usedServers[0] : null,
                used: license.usedServers.length > 0,
                usedBy: license.usedServers.length > 0 ? 'database' : null,
                usedAt: license.usedServers.length > 0 ? license.createdAt : null
            });
        });

        // Load from JSON file for backward compatibility
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

// Create sample licenses in database
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

// Cache server keys for better performance
async function updateServerKeyCache() {
    try {
        const now = Date.now();
        if (now - lastCacheUpdate < CACHE_TTL && serverKeyCache.size > 0) {
            return; // Use cache if still valid
        }
        
        const serverKeys = await ServerKey.find({ isActive: true }).lean();
        serverKeyCache.clear();
        
        serverKeys.forEach(key => {
            serverKeyCache.set(key.key, key);
        });
        
        lastCacheUpdate = now;
        console.log(`Updated server key cache with ${serverKeyCache.size} keys`);
    } catch (error) {
        console.error('Error updating server key cache:', error);
    }
}

// Check if plugin is enabled for server and has valid license
async function isPluginEnabled(serverKey) {
    try {
        await updateServerKeyCache();
        
        const serverKeyData = serverKeyCache.get(serverKey);
        if (!serverKeyData || !serverKeyData.isActive) {
            return false;
        }
        
        // Check for valid licenses
        const validLicenses = Array.from(validLicenseKeys.values()).filter(license => {
            // Check if license is active and not expired
            if (!license.isActive || new Date(license.validUntil) < new Date()) {
                return false;
            }
            
            // Global licenses can be used by any server
            if (license.type === 'GLOBAL' || !license.serverKey) {
                // Check if server limit is reached (for non-unlimited licenses)
                if (license.maxServers && license.maxServers > 0 && license.usedServers) {
                    return license.usedServers.length < license.maxServers;
                }
                return true;
            }
            
            // Server-specific licenses
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

// Middleware to check server key
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

        // Auto-create server key if it doesn't exist
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
                await updateServerKeyCache(); // Refresh cache
                validKey = serverKeyCache.get(serverKey);
                
                console.log(`Auto-created server key: ${serverKey}`);
            } catch (error) {
                if (error.code !== 11000) { // Ignore duplicate key errors
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

// Initialize default server keys on startup
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

// Routes

// Check user status
app.post('/api/checkUser', checkServerKey, async (req, res) => {
    try {
        const { username } = req.body;
        const serverKey = req.serverKey;
        
        if (!username) {
            return res.status(400).json({ error: 'Username required' });
        }
        
        const user = await User.findOne({ username, serverKey }).lean();
        
        if (user) {
            res.json({ 
                exists: true, 
                action: 'login',
                message: 'User exists, please use /login'
            });
        } else {
            res.json({ 
                exists: false, 
                action: 'register',
                message: 'New user, please use /register'
            });
        }
    } catch (error) {
        console.error('Check user error:', error);
        res.status(500).json({ error: 'Failed to check user' });
    }
});

// Register endpoint - FIXED LICENSE LOGIC
app.post('/api/register', checkServerKey, async (req, res) => {
    try {
        const { username, email, password, licenseKey } = req.body;
        const serverKey = req.serverKey;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        // Check if user already exists
        const existingUser = await User.findOne({ username, serverKey });
        
        if (existingUser) {
            return res.status(400).json({ 
                error: 'User already exists, please use /login instead',
                code: 'USER_EXISTS'
            });
        }
        
        // License key is optional - if provided, check it but don't mark as "used"
        // Multiple users can register with the same license key
        if (licenseKey) {
            const keyData = validLicenseKeys.get(licenseKey);
            
            if (!keyData) {
                return res.status(400).json({ error: 'Invalid license key' });
            }
            
            if (!keyData.isActive || new Date(keyData.validUntil) < new Date()) {
                return res.status(400).json({ error: 'License key expired' });
            }
            
            // Check if it's a server-specific license
            if (keyData.type === 'SERVER_SPECIFIC' && keyData.serverKey && keyData.serverKey !== serverKey) {
                return res.status(400).json({ error: 'License key not valid for this server' });
            }
            
            // For database licenses, add server to usedServers if not already there
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
        
        // Update server user count
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

// Login endpoint
app.post('/api/login', checkServerKey, async (req, res) => {
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
        
        // Check if user is banned
        if (user.isBanned) {
            return res.status(403).json({ 
                error: user.banMessage || 'You are banned from this server',
                banned: true
            });
        }
        
        // Check login attempts
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        
        if (user.lastAttempt > oneHourAgo && user.loginAttempts >= 5) {
            return res.status(429).json({ 
                error: 'Too many login attempts. Try again later.',
                code: 'RATE_LIMITED'
            });
        }
        
        // Verify password
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
        
        // Reset login attempts on successful login
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

// Plugin status endpoint
app.get('/api/pluginStatus', checkServerKey, async (req, res) => {
    try {
        const serverKey = req.serverKey;
        const isEnabled = await isPluginEnabled(serverKey);
        
        // Get license info
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

// Enhanced stats endpoint with more data
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
        
        // Get data for charts
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

// Helper functions for enhanced analytics
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
                    $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
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
    // This is a simplified version - in reality you'd use IP geolocation
    const users = await User.find({ serverKey, location: { $exists: true, $ne: '' } })
        .limit(1000)
        .lean();
    
    const countries = {};
    users.forEach(user => {
        if (user.location) {
            // Simple country extraction (you'd use a proper IP geolocation service)
            const country = user.location.includes('::1') ? 'Localhost' : 'Unknown';
            countries[country] = (countries[country] || 0) + 1;
        }
    });
    
    return Object.entries(countries)
        .map(([country, count]) => ({ country, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);
}

// Admin endpoints
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

// Server key management
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

// License management
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
        await loadLicenseKeys(); // Refresh cache
        
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
        await loadLicenseKeys(); // Refresh cache
        res.json({ message: 'License deleted successfully' });
    } catch (error) {
        console.error('License deletion error:', error);
        res.status(500).json({ error: 'Failed to delete license' });
    }
});

// Token validation endpoint
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

// System info endpoint
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

// Utility function to generate license keys
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
    return result;
}

// Initialize application
async function initializeApp() {
    try {
        console.log('Initializing AdvanceAuth API...');
        
        // Load license keys from database and JSON
        await loadLicenseKeys();
        
        // Initialize server keys in database
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

// Serve admin panel
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));


app.get('/advancedAuth/dash', (req, res) => {
    res.sendFile(path.join(__dirname, "dash.html"));
});

app.get('/advancedAuth/', (req, res) => {
    res.sendFile(path.join(__dirname, "advanceAuth.html"));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
})

app.get('/advancedAuth/dash/:token', (req, res) => {
    res.sendFile(path.join(__dirname, "dash.html"));
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        author: 'DEVELOPER.RS',
        company: 'Zenuxs'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        message: 'The requested API endpoint does not exist',
        version: '2.0.0'
    });
});

// Error handler
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        message: 'An unexpected error occurred'
    });
});

// Graceful shutdown
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

// Start the application
initializeApp();