# Test Credentials for Messaging App

This file contains test credentials that are now configured via environment variables.

## Environment Configuration

The app now uses environment variables for all configuration including sample data. Copy `env.example` to `.env` and modify as needed:

```bash
cp env.example .env
```

## Sample Users (from environment variables)

The following users are created from the `SAMPLE_USERS` environment variable:

### User 1: john_doe
- **Username:** john_doe
- **Password:** password123
- **Email:** john@example.com

### User 2: jane_smith
- **Username:** jane_smith
- **Password:** password123
- **Email:** jane@example.com

### User 3: mike_johnson
- **Username:** mike_johnson
- **Password:** password123
- **Email:** mike@example.com

### User 4: sarah_wilson
- **Username:** sarah_wilson
- **Password:** password123
- **Email:** sarah@example.com

### User 5: alex_brown
- **Username:** alex_brown
- **Password:** password123
- **Email:** alex@example.com

## How to Test Real-time Messaging

1. **Start the server:**
   ```bash
   node server.js
   ```

2. **Open two browser windows:**
   - Window 1: Login as `john_doe`
   - Window 2: Login as `jane_smith`

3. **Test messaging:**
   - In Window 1: Select `jane_smith` from contacts
   - In Window 2: Select `john_doe` from contacts
   - Send messages between the two windows to test real-time functionality

## Customizing Sample Data

To customize the sample data, edit the `.env` file:

```bash
# Disable sample data creation
CREATE_SAMPLE_DATA=false

# Or modify the sample users
SAMPLE_USERS=[
  {
    "username": "your_username",
    "email": "your_email@example.com",
    "password": "your_password",
    "full_name": "Your Full Name",
    "bio": "Your bio",
    "phone_number": "+1234567890"
  }
]
```

## API Testing

### Login Test
```bash
curl -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"password123"}'
```

### Send Message Test
```bash
# First get token
TOKEN=$(curl -s -X POST http://localhost:3002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"password123"}' | jq -r '.token')

# Then send message
curl -X POST http://localhost:3002/api/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"receiverId":2,"content":"Hello from API!","messageType":"text"}'
```

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `CREATE_SAMPLE_DATA` | Enable/disable sample data creation | `true` |
| `SAMPLE_USERS` | JSON array of sample users | See env.example |
| `SAMPLE_GROUPS` | JSON array of sample groups | See env.example |
| `SAMPLE_CHANNELS` | JSON array of sample channels | See env.example |
| `SAMPLE_STORIES` | JSON array of sample stories | See env.example |
| `SAMPLE_MESSAGES` | JSON array of sample messages | See env.example |
| `SAMPLE_CONTACTS` | JSON array of sample contacts | See env.example |

## Security Notes

- **Change default passwords** in production
- **Update security keys** (JWT_SECRET, ENCRYPTION_KEY, etc.)
- **Use strong passwords** for all users
- **Disable sample data** in production by setting `CREATE_SAMPLE_DATA=false`

## Troubleshooting

### If messages don't appear in real-time:
1. Check browser console for Socket.IO connection errors
2. Verify both users are logged in
3. Check server logs for Socket.IO connection messages
4. Ensure the backend server is running on port 3002

### If login fails:
1. Check if the user exists in the database
2. Verify the password is correct
3. Check server logs for authentication errors

## Database Check
```bash
# Check existing users
sqlite3 database/messaging.db "SELECT id, username, email FROM users;"

# Check messages
sqlite3 database/messaging.db "SELECT * FROM messages ORDER BY created_at DESC LIMIT 5;"
``` 