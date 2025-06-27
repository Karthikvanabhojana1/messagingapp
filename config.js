module.exports = {
    // Server Configuration
    port: process.env.PORT || 3002,
    nodeEnv: process.env.NODE_ENV || 'development',
    clientUrl: process.env.CLIENT_URL || 'http://localhost:3000',

    // Security Keys (Change these in production!)
    jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production',
    sessionSecret: process.env.SESSION_SECRET || 'your-super-secret-session-key-change-this-in-production',
    encryptionKey: process.env.ENCRYPTION_KEY || 'your-encryption-key-32-chars-long!',

    // Database Configuration
    dbPath: process.env.DB_PATH || './database/messaging.db',

    // Rate Limiting
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
    rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,

    // Security Settings
    bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12,
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
    sessionMaxAge: parseInt(process.env.SESSION_MAX_AGE) || 86400000,

    // Sample Data Configuration
    createSampleData: process.env.CREATE_SAMPLE_DATA === 'true',
    sampleUsers: (() => {
        try {
            return process.env.SAMPLE_USERS ? JSON.parse(process.env.SAMPLE_USERS) : [];
        } catch (error) {
            console.warn('Failed to parse SAMPLE_USERS, using default:', error.message);
            return [];
        }
    })(),
    sampleGroups: (() => {
        try {
            return process.env.SAMPLE_GROUPS ? JSON.parse(process.env.SAMPLE_GROUPS) : [];
        } catch (error) {
            console.warn('Failed to parse SAMPLE_GROUPS, using default:', error.message);
            return [];
        }
    })(),
    sampleChannels: (() => {
        try {
            return process.env.SAMPLE_CHANNELS ? JSON.parse(process.env.SAMPLE_CHANNELS) : [];
        } catch (error) {
            console.warn('Failed to parse SAMPLE_CHANNELS, using default:', error.message);
            return [];
        }
    })(),
    sampleStories: (() => {
        try {
            return process.env.SAMPLE_STORIES ? JSON.parse(process.env.SAMPLE_STORIES) : [];
        } catch (error) {
            console.warn('Failed to parse SAMPLE_STORIES, using default:', error.message);
            return [];
        }
    })(),
    sampleMessages: (() => {
        try {
            return process.env.SAMPLE_MESSAGES ? JSON.parse(process.env.SAMPLE_MESSAGES) : [];
        } catch (error) {
            console.warn('Failed to parse SAMPLE_MESSAGES, using default:', error.message);
            return [];
        }
    })(),
    sampleContacts: (() => {
        try {
            return process.env.SAMPLE_CONTACTS ? JSON.parse(process.env.SAMPLE_CONTACTS) : [];
        } catch (error) {
            console.warn('Failed to parse SAMPLE_CONTACTS, using default:', error.message);
            return [];
        }
    })()
}; 