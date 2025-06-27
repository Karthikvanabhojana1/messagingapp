# 🚀 SecureChat - WhatsApp/Telegram Clone

A comprehensive, feature-rich messaging application that replicates the core functionality of WhatsApp and Telegram with enhanced security features.

![SecureChat](https://img.shields.io/badge/SecureChat-v2.0-blue)
![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![Socket.IO](https://img.shields.io/badge/Socket.IO-Real--time-orange)
![SQLite](https://img.shields.io/badge/SQLite-Database-yellow)

## ✨ Features

### 🔐 **Security & Authentication**

- **End-to-End Encryption**: All messages encrypted with AES-256
- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: Bcrypt password security
- **Session Management**: Secure user sessions with expiration
- **Two-Factor Authentication**: Ready for 2FA implementation

### 💬 **Messaging Features**

- **Real-time Messaging**: Instant message delivery via Socket.IO
- **Message Types**: Text, images, videos, audio, documents, locations
- **Message Status**: Sent, delivered, read receipts
- **Typing Indicators**: Real-time typing notifications
- **Message Reactions**: Emoji reactions to messages
- **Reply Messages**: Reply to specific messages
- **Forward Messages**: Forward messages to other chats
- **Message Editing**: Edit sent messages
- **Message Deletion**: Delete messages with auto-delete options

### 👥 **Chat Types**

- **Direct Messages**: One-on-one conversations
- **Group Chats**: Multi-user conversations (up to 256 members)
- **Channels**: Broadcast messages to subscribers
- **Private Groups**: Invite-only group chats
- **Public Channels**: Discoverable channels

### 📱 **User Interface**

- **Modern Design**: Clean, responsive UI inspired by WhatsApp/Telegram
- **Dark Mode**: Toggle between light and dark themes
- **Tab Navigation**: Separate tabs for chats, groups, channels, calls
- **Search Functionality**: Search contacts, groups, and messages
- **Responsive Design**: Works on desktop, tablet, and mobile

### 📸 **Stories & Status**

- **Story Creation**: Create text, image, and video stories
- **Story Viewing**: View stories from contacts
- **Story Expiration**: Stories automatically expire after 24 hours
- **Custom Backgrounds**: Colorful story backgrounds
- **Story Reactions**: React to stories

### 📞 **Voice & Video Calls**

- **Voice Calls**: Make and receive voice calls
- **Video Calls**: High-quality video calling
- **Call History**: Track call history and duration
- **Call Status**: Missed, answered, ended call tracking

### 📎 **File Sharing**

- **Image Sharing**: Share photos with preview
- **Video Sharing**: Share videos with thumbnails
- **Audio Sharing**: Share voice messages and audio files
- **Document Sharing**: Share PDFs, documents, and files
- **Location Sharing**: Share real-time location
- **Contact Sharing**: Share contact information
- **Sticker Support**: Send and receive stickers

### 👤 **User Profiles**

- **Profile Management**: Edit profile information
- **Avatar Support**: Custom profile pictures
- **Status Updates**: Custom status messages
- **Online Status**: Real-time online/offline indicators
- **Last Seen**: Track when users were last active

### ⚙️ **Settings & Customization**

- **Notification Settings**: Customize notification preferences
- **Privacy Settings**: Control message previews and read receipts
- **Auto-lock**: Automatic app locking for security
- **Theme Customization**: Choose between light and dark themes
- **Language Support**: Multi-language interface ready

### 🔍 **Advanced Features**

- **Message Search**: Search through message history
- **Contact Management**: Add, remove, and block contacts
- **Group Management**: Create, join, and manage groups
- **Channel Management**: Create and subscribe to channels
- **Admin Controls**: Group and channel administration
- **Message Encryption**: Military-grade message encryption

## 🛠️ Technology Stack

### Backend

- **Node.js**: Server-side JavaScript runtime
- **Express.js**: Web application framework
- **Socket.IO**: Real-time bidirectional communication
- **SQLite**: Lightweight database
- **JWT**: JSON Web Token authentication
- **Bcrypt**: Password hashing
- **Crypto-js**: Message encryption
- **Multer**: File upload handling

### Frontend

- **HTML5**: Semantic markup
- **CSS3**: Modern styling with Flexbox and Grid
- **JavaScript (ES6+)**: Modern JavaScript features
- **Font Awesome**: Icon library
- **Socket.IO Client**: Real-time communication

### Security

- **AES-256**: Message encryption
- **JWT**: Secure authentication
- **Bcrypt**: Password security
- **Helmet**: Security headers
- **Rate Limiting**: API protection
- **CORS**: Cross-origin resource sharing

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- Git

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd messagingapp
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Set up environment variables**

   ```bash
   cp env.example .env
   # Edit .env file to customize configuration
   ```

4. **Initialize the database**

   ```bash
   node scripts/init-database.js
   ```

5. **Start the development server**

   ```bash
   npm run dev
   ```

6. **Open your browser**
   ```
   http://localhost:3002
   ```

### Environment Configuration

The app uses environment variables for all configuration. Copy `env.example` to `.env` and customize:

```env
# Server Configuration
PORT=3002
NODE_ENV=development
CLIENT_URL=http://localhost:3000

# Security Keys (Change these in production!)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
SESSION_SECRET=your-super-secret-session-key-change-this-in-production
ENCRYPTION_KEY=your-encryption-key-32-chars-long!

# Database Configuration
DB_PATH=./database/messaging.db

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Security Settings
BCRYPT_SALT_ROUNDS=12
JWT_EXPIRES_IN=24h
SESSION_MAX_AGE=86400000

# Sample Data Configuration
CREATE_SAMPLE_DATA=true
SAMPLE_USERS=[...]  # JSON array of sample users
SAMPLE_GROUPS=[...] # JSON array of sample groups
SAMPLE_CHANNELS=[...] # JSON array of sample channels
SAMPLE_STORIES=[...] # JSON array of sample stories
SAMPLE_MESSAGES=[...] # JSON array of sample messages
SAMPLE_CONTACTS=[...] # JSON array of sample contacts
```

### Sample Users

The database comes with sample users configured via environment variables:

| Username       | Password      | Full Name    |
| -------------- | ------------- | ------------ |
| `john_doe`     | `password123` | John Doe     |
| `jane_smith`   | `password123` | Jane Smith   |
| `mike_johnson` | `password123` | Mike Johnson |
| `sarah_wilson` | `password123` | Sarah Wilson |
| `alex_brown`   | `password123` | Alex Brown   |

**To customize users:** Edit the `SAMPLE_USERS` array in your `.env` file.

**To disable sample data:** Set `CREATE_SAMPLE_DATA=false` in your `.env` file.

## 📁 Project Structure

```
messagingapp/
├── public/                 # Frontend files
│   ├── index.html         # Main HTML file
│   ├── styles.css         # CSS styles
│   └── script.js          # Frontend JavaScript
├── database/              # Database files
│   └── messaging.db       # SQLite database
├── uploads/               # File uploads
├── scripts/               # Database scripts
│   └── init-database.js   # Database initialization
├── server.js              # Main server file
├── config.js              # Configuration
├── package.json           # Dependencies
└── README.md             # This file
```

## 🔧 Configuration

### Environment Variables

The app uses environment variables for all configuration. Copy `env.example` to `.env` and customize:

```env
# Server Configuration
PORT=3002
NODE_ENV=development
CLIENT_URL=http://localhost:3000

# Security Keys (Change these in production!)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
SESSION_SECRET=your-super-secret-session-key-change-this-in-production
ENCRYPTION_KEY=your-encryption-key-32-chars-long!

# Database Configuration
DB_PATH=./database/messaging.db

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Security Settings
BCRYPT_SALT_ROUNDS=12
JWT_EXPIRES_IN=24h
SESSION_MAX_AGE=86400000

# Sample Data Configuration
CREATE_SAMPLE_DATA=true
SAMPLE_USERS=[...]  # JSON array of sample users
SAMPLE_GROUPS=[...] # JSON array of sample groups
SAMPLE_CHANNELS=[...] # JSON array of sample channels
SAMPLE_STORIES=[...] # JSON array of sample stories
SAMPLE_MESSAGES=[...] # JSON array of sample messages
SAMPLE_CONTACTS=[...] # JSON array of sample contacts
```

### Database Configuration

The app uses SQLite by default. The database file is created automatically in the `database/` directory.

### Sample Data Management

- **Enable/Disable**: Set `CREATE_SAMPLE_DATA=true/false`
- **Customize Users**: Edit the `SAMPLE_USERS` JSON array
- **Customize Groups**: Edit the `SAMPLE_GROUPS` JSON array
- **Customize Channels**: Edit the `SAMPLE_CHANNELS` JSON array
- **Customize Messages**: Edit the `SAMPLE_MESSAGES` JSON array
- **Customize Contacts**: Edit the `SAMPLE_CONTACTS` JSON array

See `env.example` for complete configuration examples.

## 📱 Usage Guide

### Getting Started

1. **Register/Login**: Create a new account or use the test credentials
2. **Add Contacts**: Start conversations with other users
3. **Create Groups**: Invite multiple users to group chats
4. **Join Channels**: Subscribe to broadcast channels
5. **Share Media**: Send photos, videos, and documents
6. **Create Stories**: Share moments with your contacts

### Navigation

- **Chats Tab**: View and manage direct conversations
- **Groups Tab**: Access group chats and create new groups
- **Channels Tab**: Browse and subscribe to channels
- **Calls Tab**: View call history and make new calls

### Messaging

- **Send Messages**: Type and press Enter or click send
- **Attach Files**: Use the paperclip icon to share media
- **Use Emojis**: Click the smiley icon for emoji picker
- **Reply to Messages**: Right-click on messages to reply
- **React to Messages**: Add emoji reactions

### Settings

- **Profile**: Click your avatar to access profile settings
- **Theme**: Toggle between light and dark modes
- **Notifications**: Customize notification preferences
- **Security**: Manage privacy and security settings

## 🔒 Security Features

### Message Encryption

- All messages are encrypted using AES-256 encryption
- Encryption keys are unique per user
- Messages are decrypted only on the recipient's device

### Authentication

- JWT tokens for secure authentication
- Token expiration and refresh mechanisms
- Secure password hashing with bcrypt

### Privacy

- End-to-end encryption for all communications
- No message content stored in plain text
- User sessions with automatic expiration
- Configurable privacy settings

## 🚀 Deployment

### Production Setup

1. **Set environment variables** for production
2. **Use a production database** (PostgreSQL, MySQL)
3. **Enable HTTPS** with SSL certificates
4. **Set up reverse proxy** (Nginx, Apache)
5. **Configure PM2** for process management

### Docker Deployment

```bash
# Build the image
docker build -t securechat .

# Run the container
docker run -p 3002:3002 securechat
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/your-repo/issues) page
2. Create a new issue with detailed information
3. Contact the development team

## 🔮 Roadmap

### Upcoming Features

- [ ] **Video Calls**: WebRTC video calling
- [ ] **Sending Files**: End to end Encrypted files still testing it
- [ ] **Voice Messages**: Audio message recording
- [ ] **Message Pinning**: Pin important messages
- [ ] **Message Translation**: Multi-language message translation
- [ ] **Advanced Search**: Full-text message search
- [ ] **Message Scheduling**: Schedule messages for later
- [ ] **Custom Themes**: User-defined color themes
- [ ] **Bot Support**: Chatbot integration
- [ ] **API Documentation**: REST API documentation
- [ ] **Mobile App**: React Native mobile application

### Performance Improvements

- [ ] **Message Pagination**: Efficient message loading
- [ ] **File Compression**: Optimize media file sizes
- [ ] **Caching**: Redis caching for better performance
- [ ] **CDN Integration**: Content delivery network
- [ ] **Database Optimization**: Query optimization and indexing

## 🙏 Acknowledgments

- **WhatsApp** for inspiration on messaging features
- **Telegram** for channel and group concepts
- **Socket.IO** for real-time communication
- **Font Awesome** for beautiful icons

---


_This project is for educational purposes and demonstrates modern web development practices with a focus on security and user experience._
