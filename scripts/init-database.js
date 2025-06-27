const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto-js');
const path = require('path');
const config = require('../config');

// Create database directory if it doesn't exist
const dbPath = path.join(__dirname, '..', 'database', 'messaging.db');
const db = new sqlite3.Database(dbPath);

console.log('Initializing enhanced messaging database...');
console.log('Sample data creation:', config.createSampleData ? 'enabled' : 'disabled');

db.serialize(async () => {
    try {
        // Create tables
        console.log('Creating enhanced tables...');
        
        // Users table (enhanced)
        await runQuery(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            phone_number TEXT UNIQUE,
            full_name TEXT,
            bio TEXT,
            avatar_url TEXT,
            status TEXT DEFAULT 'Hey there! I am using SecureChat',
            is_online BOOLEAN DEFAULT 0,
            last_seen DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Groups table
        await runQuery(`CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            avatar_url TEXT,
            created_by INTEGER NOT NULL,
            is_private BOOLEAN DEFAULT 0,
            max_members INTEGER DEFAULT 256,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )`);

        // Group members table
        await runQuery(`CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'member', -- admin, member, moderator
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(group_id, user_id)
        )`);

        // Channels table
        await runQuery(`CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            avatar_url TEXT,
            created_by INTEGER NOT NULL,
            is_public BOOLEAN DEFAULT 1,
            subscriber_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )`);

        // Channel subscribers table
        await runQuery(`CREATE TABLE IF NOT EXISTS channel_subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            subscribed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (channel_id) REFERENCES channels (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(channel_id, user_id)
        )`);

        // Enhanced messages table
        await runQuery(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER, -- NULL for group/channel messages
            group_id INTEGER, -- NULL for direct messages
            channel_id INTEGER, -- NULL for direct/group messages
            encrypted_content TEXT NOT NULL,
            message_type TEXT DEFAULT 'text', -- text, image, video, audio, document, location, contact, sticker, gif
            file_url TEXT,
            file_name TEXT,
            file_size INTEGER,
            thumbnail_url TEXT,
            duration INTEGER, -- for audio/video
            reply_to_id INTEGER, -- for reply messages
            forward_from_id INTEGER, -- for forwarded messages
            is_edited BOOLEAN DEFAULT 0,
            edited_at DATETIME,
            is_deleted BOOLEAN DEFAULT 0,
            deleted_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id),
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (channel_id) REFERENCES channels (id),
            FOREIGN KEY (reply_to_id) REFERENCES messages (id),
            FOREIGN KEY (forward_from_id) REFERENCES messages (id)
        )`);

        // Message reactions table
        await runQuery(`CREATE TABLE IF NOT EXISTS message_reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            reaction TEXT NOT NULL, -- emoji
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES messages (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(message_id, user_id, reaction)
        )`);

        // Stories/Status table
        await runQuery(`CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            media_url TEXT,
            media_type TEXT, -- image, video, text
            background_color TEXT,
            text_color TEXT,
            font_style TEXT,
            expires_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        // Story views table
        await runQuery(`CREATE TABLE IF NOT EXISTS story_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            story_id INTEGER NOT NULL,
            viewer_id INTEGER NOT NULL,
            viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (story_id) REFERENCES stories (id),
            FOREIGN KEY (viewer_id) REFERENCES users (id),
            UNIQUE(story_id, viewer_id)
        )`);

        // Calls table
        await runQuery(`CREATE TABLE IF NOT EXISTS calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caller_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            call_type TEXT NOT NULL, -- voice, video
            status TEXT NOT NULL, -- ringing, answered, missed, ended
            start_time DATETIME,
            end_time DATETIME,
            duration INTEGER, -- in seconds
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (caller_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )`);

        // Contacts table (enhanced)
        await runQuery(`CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            nickname TEXT,
            is_favorite BOOLEAN DEFAULT 0,
            is_blocked BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (contact_user_id) REFERENCES users (id),
            UNIQUE(user_id, contact_user_id)
        )`);

        // User sessions table
        await runQuery(`CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            device_info TEXT,
            ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        // User settings table
        await runQuery(`CREATE TABLE IF NOT EXISTS user_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            setting_key TEXT NOT NULL,
            setting_value TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, setting_key)
        )`);

        // Stickers table
        await runQuery(`CREATE TABLE IF NOT EXISTS stickers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            emoji TEXT,
            image_url TEXT NOT NULL,
            pack_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Sticker packs table
        await runQuery(`CREATE TABLE IF NOT EXISTS sticker_packs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            author TEXT,
            cover_image_url TEXT,
            is_public BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Hidden messages table (for 'Delete for Me')
        await runQuery(`CREATE TABLE IF NOT EXISTS hidden_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            hidden_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (message_id) REFERENCES messages (id),
            UNIQUE(user_id, message_id)
        )`);

        console.log('Database tables created successfully');

        // Check if sample data should be created
        if (!config.createSampleData) {
            console.log('Sample data creation is disabled. Skipping...');
            return;
        }

        // Check if sample data already exists
        const userCount = await getQuery('SELECT COUNT(*) as count FROM users');
        
        if (userCount.count === 0) {
            console.log('Adding enhanced sample data from environment variables...');
            
            // Create sample users from environment variables
            if (config.sampleUsers && config.sampleUsers.length > 0) {
                for (const user of config.sampleUsers) {
                    const passwordHash = await bcrypt.hash(user.password, config.bcryptSaltRounds);
                    const publicKey = crypto.lib.WordArray.random(32).toString();
                    
                    await runQuery(
                        'INSERT INTO users (username, email, password_hash, public_key, full_name, bio, phone_number) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [user.username, user.email, passwordHash, publicKey, user.full_name, user.bio, user.phone_number]
                    );
                }
                console.log(`Created ${config.sampleUsers.length} sample users`);
            }

            // Create sample groups from environment variables
            if (config.sampleGroups && config.sampleGroups.length > 0) {
                for (const group of config.sampleGroups) {
                    const result = await runQuery(
                        'INSERT INTO groups (name, description, created_by, is_private) VALUES (?, ?, ?, ?)',
                        [group.name, group.description, group.created_by, group.is_private || false]
                    );
                    
                    // Add members to groups
                    const groupId = result.lastID;
                    const members = [1, 2, 3, 4, 5]; // All users
                    for (const memberId of members) {
                        await runQuery(
                            'INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
                            [groupId, memberId, memberId === group.created_by ? 'admin' : 'member']
                        );
                    }
                }
                console.log(`Created ${config.sampleGroups.length} sample groups`);
            }

            // Create sample channels from environment variables
            if (config.sampleChannels && config.sampleChannels.length > 0) {
                for (const channel of config.sampleChannels) {
                    const result = await runQuery(
                        'INSERT INTO channels (name, description, created_by) VALUES (?, ?, ?)',
                        [channel.name, channel.description, channel.created_by]
                    );
                    
                    // Add subscribers to channels
                    const channelId = result.lastID;
                    const subscribers = [1, 2, 3, 4, 5]; // All users
                    for (const subscriberId of subscribers) {
                        await runQuery(
                            'INSERT INTO channel_subscribers (channel_id, user_id) VALUES (?, ?)',
                            [channelId, subscriberId]
                        );
                    }
                }
                console.log(`Created ${config.sampleChannels.length} sample channels`);
            }

            // Create sample stories from environment variables
            if (config.sampleStories && config.sampleStories.length > 0) {
                for (const story of config.sampleStories) {
                    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
                    await runQuery(
                        'INSERT INTO stories (user_id, content, media_type, background_color, expires_at) VALUES (?, ?, ?, ?, ?)',
                        [story.user_id, story.content, story.media_type, story.background_color, expiresAt.toISOString()]
                    );
                }
                console.log(`Created ${config.sampleStories.length} sample stories`);
            }

            // Create sample messages from environment variables
            if (config.sampleMessages && config.sampleMessages.length > 0) {
                for (const msg of config.sampleMessages) {
                    const encryptedContent = crypto.AES.encrypt(msg.content, config.encryptionKey).toString();
                    const timestamp = new Date(Date.now() - Math.random() * 86400000).toISOString();
                    
                    if (msg.receiver) {
                        await runQuery(
                            'INSERT INTO messages (sender_id, receiver_id, encrypted_content, message_type, created_at) VALUES (?, ?, ?, ?, ?)',
                            [msg.sender, msg.receiver, encryptedContent, msg.type, timestamp]
                        );
                    } else if (msg.group) {
                        await runQuery(
                            'INSERT INTO messages (sender_id, group_id, encrypted_content, message_type, created_at) VALUES (?, ?, ?, ?, ?)',
                            [msg.sender, msg.group, encryptedContent, msg.type, timestamp]
                        );
                    } else if (msg.channel) {
                        await runQuery(
                            'INSERT INTO messages (sender_id, channel_id, encrypted_content, message_type, created_at) VALUES (?, ?, ?, ?, ?)',
                            [msg.sender, msg.channel, encryptedContent, msg.type, timestamp]
                        );
                    }
                }
                console.log(`Created ${config.sampleMessages.length} sample messages`);
            }

            // Create sample contacts from environment variables
            if (config.sampleContacts && config.sampleContacts.length > 0) {
                for (const contact of config.sampleContacts) {
                    await runQuery(
                        'INSERT INTO contacts (user_id, contact_user_id, nickname) VALUES (?, ?, ?)',
                        [contact.user_id, contact.contact_user_id, contact.nickname]
                    );
                }
                console.log(`Created ${config.sampleContacts.length} sample contacts`);
            }

            console.log('✅ All sample data created successfully from environment variables!');
        } else {
            console.log('Sample data already exists. Skipping creation...');
        }

    } catch (error) {
        console.error('❌ Error initializing database:', error);
        throw error;
    } finally {
        db.close((err) => {
            if (err) {
                console.error('Error closing database:', err.message);
            } else {
                console.log('Database connection closed.');
            }
        });
    }
});

// Helper functions
function runQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) {
                reject(err);
            } else {
                resolve({ lastID: this.lastID, changes: this.changes });
            }
        });
    });
}

function getQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
} 