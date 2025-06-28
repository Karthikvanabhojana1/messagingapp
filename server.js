// Load environment variables
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto-js');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const config = require('./config');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: ['http://localhost:3000', 'http://localhost:3001', config.clientUrl],
        methods: ["GET", "POST"],
        credentials: true
    }
});

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "ws:", "wss:"]
        }
    }
}));

app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001', config.clientUrl],
    credentials: true
}));

// Trust proxy for rate limiting
app.set('trust proxy', 1);

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: config.nodeEnv === 'production',
        httpOnly: true,
        maxAge: config.sessionMaxAge,
        sameSite: 'strict'
    }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Database initialization
const db = new sqlite3.Database(config.dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

// Initialize database tables
function initializeDatabase() {
    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            is_online BOOLEAN DEFAULT 0
        )`);

        // Messages table
        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            encrypted_content TEXT NOT NULL,
            message_type TEXT DEFAULT 'text',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )`);

        // User sessions table
        db.run(`CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        // Contacts table
        db.run(`CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            nickname TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (contact_user_id) REFERENCES users (id),
            UNIQUE(user_id, contact_user_id)
        )`);

        console.log('Database tables initialized');
    });
}

// Encryption utilities
function encryptMessage(message) {
    return crypto.AES.encrypt(message, config.encryptionKey).toString();
}

function decryptMessage(encryptedMessage) {
    const bytes = crypto.AES.decrypt(encryptedMessage, config.encryptionKey);
    return bytes.toString(crypto.enc.Utf8);
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, config.jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// API Routes

// Verify authentication token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    
    db.get('SELECT id, username, email, public_key, created_at, last_login, is_online FROM users WHERE id = ?',
        [userId], (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json({ 
                message: 'Token is valid',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    publicKey: user.public_key,
                    created_at: user.created_at,
                    last_login: user.last_login,
                    is_online: user.is_online
                }
            });
        });
});

// User registration
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Validate password strength
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters long' });
        }

        // Check if user already exists
        db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row) {
                return res.status(400).json({ error: 'Username or email already exists' });
            }

            // Hash password
            const passwordHash = await bcrypt.hash(password, config.bcryptSaltRounds);

            // Generate public key for encryption
            const publicKey = crypto.lib.WordArray.random(32).toString();

            // Insert new user
            db.run('INSERT INTO users (username, email, password_hash, public_key) VALUES (?, ?, ?, ?)',
                [username, email, passwordHash, publicKey],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Error creating user' });
                    }

                    const token = jwt.sign(
                        { userId: this.lastID, username },
                        config.jwtSecret,
                        { expiresIn: config.jwtExpiresIn }
                    );

                    res.status(201).json({
                        message: 'User registered successfully',
                        token,
                        user: { id: this.lastID, username, email }
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// User login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP, is_online = 1 WHERE id = ?', [user.id]);

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            config.jwtSecret,
            { expiresIn: config.jwtExpiresIn }
        );

        // Create session
        const sessionToken = uuidv4();
        const expiresAt = new Date(Date.now() + config.sessionMaxAge);

        db.run('INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)',
            [user.id, sessionToken, expiresAt.toISOString()]);

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                publicKey: user.public_key
            }
        });
    });
});

// User logout
app.post('/api/logout', authenticateToken, (req, res) => {
    const userId = req.user.userId;

    // Deactivate all sessions for user
    db.run('UPDATE user_sessions SET is_active = 0 WHERE user_id = ?', [userId]);
    
    // Set user as offline
    db.run('UPDATE users SET is_online = 0 WHERE id = ?', [userId]);

    res.json({ message: 'Logout successful' });
});

// Get user profile
app.get('/api/profile', authenticateToken, (req, res) => {
    const userId = req.user.userId;

    db.get('SELECT id, username, email, public_key, created_at, last_login, is_online FROM users WHERE id = ?',
        [userId], (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json({ user });
        });
});

// Get all users (for contact list)
app.get('/api/users', authenticateToken, (req, res) => {
    const currentUserId = req.user.userId;

    db.all(`
        SELECT u.id, u.username, u.email, u.is_online, u.last_login,
               c.nickname
        FROM users u
        LEFT JOIN contacts c ON (c.user_id = ? AND c.contact_user_id = u.id)
        WHERE u.id != ?
        ORDER BY u.username
    `, [currentUserId, currentUserId], (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ users });
    });
});

// Add contact
app.post('/api/contacts', authenticateToken, (req, res) => {
    const { contactUserId, nickname } = req.body;
    const userId = req.user.userId;

    if (!contactUserId) {
        return res.status(400).json({ error: 'Contact user ID required' });
    }

    db.run('INSERT OR REPLACE INTO contacts (user_id, contact_user_id, nickname) VALUES (?, ?, ?)',
        [userId, contactUserId, nickname], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Error adding contact' });
            }
            res.json({ message: 'Contact added successfully' });
        });
});

// Get messages between users
app.get('/api/messages/:userId', authenticateToken, (req, res) => {
    const currentUserId = req.user.userId;
    const otherUserId = req.params.userId;

    db.all(`
        SELECT m.*, u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE ((m.sender_id = ? AND m.receiver_id = ?) 
           OR (m.sender_id = ? AND m.receiver_id = ?))
          AND m.id NOT IN (SELECT message_id FROM hidden_messages WHERE user_id = ?)
        ORDER BY m.created_at ASC
    `, [currentUserId, otherUserId, otherUserId, currentUserId, currentUserId], (err, messages) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        // Decrypt messages
        const decryptedMessages = messages.map(msg => {
            return {
                ...msg,
                content: decryptMessage(msg.encrypted_content)
            };
        });

        res.json({ messages: decryptedMessages });
    });
});

// Send message
app.post('/api/messages', authenticateToken, (req, res) => {
    const { receiverId, content, messageType = 'text' } = req.body;
    const senderId = req.user.userId;

    if (!receiverId || !content) {
        return res.status(400).json({ error: 'Receiver ID and content required' });
    }

    // Encrypt message
    const encryptedContent = encryptMessage(content);
    const timestamp = new Date().toISOString();

    db.run(`
        INSERT INTO messages (sender_id, receiver_id, encrypted_content, message_type, created_at)
        VALUES (?, ?, ?, ?, ?)
    `, [senderId, receiverId, encryptedContent, messageType, timestamp], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Error sending message' });
        }

        const message = {
            id: this.lastID,
            sender_id: senderId,
            receiver_id: receiverId,
            content: content,
            message_type: messageType,
            created_at: timestamp,
            is_read: false
        };

        // Emit to connected clients
        console.log(`📡 Emitting message to users: ${senderId} and ${receiverId}`);
        console.log(`📨 Message content: ${content}`);
        console.log(`🕐 Message timestamp: ${message.created_at}`);
        
        // Emit message with delivery confirmation
        const messageWithDelivery = {
            ...message,
            deliveryStatus: 'sent'
        };
        
        io.to(`user_${senderId}`).to(`user_${receiverId}`).emit('new_message', messageWithDelivery);
        
        // Emit delivery confirmation to sender
        io.to(`user_${senderId}`).emit('message_delivered', {
            messageId: message.id,
            receiverId: receiverId,
            deliveredAt: new Date().toISOString()
        });
        
        console.log('✅ Message emitted successfully');

        res.status(201).json({ message: 'Message sent successfully', data: message });
    });
});

// Mark messages as read
app.put('/api/messages/read/:senderId', authenticateToken, (req, res) => {
    const currentUserId = req.user.userId;
    const senderId = req.params.senderId;

    db.all(`
        SELECT id FROM messages 
        WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
    `, [senderId, currentUserId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        const messageIds = rows.map(row => row.id);

        db.run(`
            UPDATE messages 
            SET is_read = 1 
            WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
        `, [senderId, currentUserId], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            // Emit read receipt to sender with message IDs
            io.to(`user_${senderId}`).emit('message_read', {
                readerId: currentUserId,
                messageIds
            });
            res.json({ message: 'Messages marked as read', messageIds });
        });
    });
});

// Mark specific message as read
app.put('/api/messages/:messageId/read', authenticateToken, (req, res) => {
    const currentUserId = req.user.userId;
    const messageId = req.params.messageId;

    db.run(`
        UPDATE messages 
        SET is_read = 1 
        WHERE id = ? AND receiver_id = ? AND is_read = 0
    `, [messageId, currentUserId], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (this.changes > 0) {
            // Get the message to emit read receipt
            db.get('SELECT sender_id FROM messages WHERE id = ?', [messageId], (err, message) => {
                if (!err && message) {
                    io.to(`user_${message.sender_id}`).emit('message_read', {
                        messageId: messageId,
                        readerId: currentUserId
                    });
                }
            });
        }
        
        res.json({ message: 'Message marked as read' });
    });
});

// Get groups (placeholder - would need groups table)
app.get('/api/groups', authenticateToken, (req, res) => {
    // For now, return empty array since we don't have groups table
    res.json({ groups: [] });
});

// Get channels (placeholder - would need channels table)
app.get('/api/channels', authenticateToken, (req, res) => {
    // For now, return empty array since we don't have channels table
    res.json({ channels: [] });
});

// Get stories (placeholder - would need stories table)
app.get('/api/stories', authenticateToken, (req, res) => {
    // For now, return empty array since we don't have stories table
    res.json({ stories: [] });
});

// Create story
app.post('/api/stories', authenticateToken, (req, res) => {
    // For now, return success since we don't have stories table
    res.json({ message: 'Story created successfully' });
});

// Get calls (placeholder - would need calls table)
app.get('/api/calls', authenticateToken, (req, res) => {
    // For now, return empty array since we don't have calls table
    res.json({ calls: [] });
});

// Get user settings
app.get('/api/settings', authenticateToken, (req, res) => {
    // For now, return default settings
    res.json({
        notifications: true,
        sound: true,
        darkMode: false,
        autoLockTime: 30,
        messagePreview: true,
        readReceipts: true,
        messageAutoDelete: 0
    });
});

// Save user settings
app.post('/api/settings', authenticateToken, (req, res) => {
    // For now, just return success since we don't have settings table
    res.json({ message: 'Settings saved successfully' });
});

// File upload functionality removed

// File serving functionality removed

// Socket.IO connection handling
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
        return next(new Error('Authentication error: No token provided'));
    }

    jwt.verify(token, config.jwtSecret, (err, decoded) => {
        if (err) {
            return next(new Error('Authentication error: Invalid token'));
        }
        
        socket.userId = decoded.userId;
        socket.username = decoded.username;
        next();
    });
});

io.on('connection', (socket) => {
    console.log('User connected:', socket.id, 'User:', socket.username);

    // Join user to their personal room
    socket.join(`user_${socket.userId}`);
    console.log(`User ${socket.username} (${socket.userId}) joined their room`);

    // Handle typing indicators
    socket.on('typing', (data) => {
        socket.to(`user_${data.receiverId}`).emit('user_typing', {
            userId: data.senderId,
            isTyping: data.isTyping
        });
    });

    // Handle disconnect
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id, 'User:', socket.username);
    });
});

// Serve the main app
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
server.listen(config.port, () => {
    console.log(`Server running on port ${config.port}`);
    console.log(`Visit http://localhost:${config.port} to use the app`);
    console.log(`Environment: ${config.nodeEnv}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down server...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err.message);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});

// Delete message (for me only)
app.delete('/api/messages/:messageId', authenticateToken, (req, res) => {
    const messageId = parseInt(req.params.messageId, 10);
    const userId = req.user.userId;

    // Delete for me: add to hidden_messages
    db.run('INSERT OR IGNORE INTO hidden_messages (user_id, message_id) VALUES (?, ?)', [userId, messageId], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        // Emit only to this user
        io.to(`user_${userId}`).emit('message_deleted', { messageId, scope: 'me' });
        res.json({ message: 'Message deleted for you' });
    });
});

// Update message fetch to exclude hidden messages for the current user
app.get('/api/messages/:userId', authenticateToken, (req, res) => {
    const currentUserId = req.user.userId;
    const otherUserId = req.params.userId;

    db.all(`
        SELECT m.*, u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE ((m.sender_id = ? AND m.receiver_id = ?) 
           OR (m.sender_id = ? AND m.receiver_id = ?))
          AND m.id NOT IN (SELECT message_id FROM hidden_messages WHERE user_id = ?)
        ORDER BY m.created_at ASC
    `, [currentUserId, otherUserId, otherUserId, currentUserId, currentUserId], (err, messages) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        // Decrypt messages
        const decryptedMessages = messages.map(msg => {
            return {
                ...msg,
                content: decryptMessage(msg.encrypted_content)
            };
        });

        res.json({ messages: decryptedMessages });
    });
}); 