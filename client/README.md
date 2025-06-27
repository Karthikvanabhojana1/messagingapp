# React Messaging App Frontend

A modern, responsive React frontend for the Secure Messaging App built with Material-UI.

## Features

- **Modern UI/UX**: Built with Material-UI for a professional, responsive design
- **Authentication**: Secure login/register with JWT tokens
- **Real-time Messaging**: Socket.IO integration for instant messaging
- **Contact Management**: View and manage contacts and groups
- **File Sharing**: Support for attachments and media files
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Dark/Light Theme**: Theme support (ready for implementation)

## Tech Stack

- **React 18**: Latest React with hooks and functional components
- **Material-UI (MUI)**: Modern UI component library
- **React Router**: Client-side routing
- **Axios**: HTTP client for API calls
- **Socket.IO Client**: Real-time communication
- **Context API**: State management for authentication

## Project Structure

```
src/
├── components/          # Reusable UI components
│   ├── AuthForm.js     # Login/Register forms
│   ├── Sidebar.js      # Contacts and navigation
│   └── ChatWindow.js   # Message display and input
├── context/            # React Context providers
│   └── AuthContext.js  # Authentication state management
├── pages/              # Page components
│   └── ChatPage.js     # Main chat interface
├── utils/              # Utility functions
└── App.js              # Main app component
```

## Getting Started

### Prerequisites

- Node.js 16+ and npm
- Backend server running on port 3002

### Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm start
   ```

3. Open [http://localhost:3000](http://localhost:3000) in your browser

### Development

The app will automatically proxy API requests to the backend server running on port 3002.

## Components

### AuthForm
- Handles user authentication (login/register)
- Form validation and error handling
- Tab-based interface for switching between login and register

### Sidebar
- Displays contacts and groups
- Tab navigation between contacts and groups
- Online status indicators
- Quick action buttons

### ChatWindow
- Real-time message display
- Message input with send functionality
- File attachment support (UI ready)
- Emoji picker (UI ready)
- Message timestamps and read status

### ChatPage
- Main application layout
- Combines Sidebar and ChatWindow
- Top navigation bar with user info and logout

## API Integration

The frontend communicates with the backend through the following endpoints:

- `POST /api/login` - User authentication
- `POST /api/register` - User registration
- `GET /api/auth/verify` - Token verification
- `GET /api/users` - Get contacts list
- `GET /api/groups` - Get groups list
- `GET /api/messages/:userId` - Get conversation messages
- `POST /api/messages` - Send new message

## Authentication Flow

1. User enters credentials in AuthForm
2. Credentials sent to backend via API
3. JWT token received and stored in localStorage
4. Token used for subsequent API calls
5. Protected routes check authentication status
6. Automatic logout on token expiration

## Styling

- Material-UI theme with custom colors
- Responsive design using MUI's breakpoint system
- Consistent spacing and typography
- Modern card-based layout

## Future Enhancements

- [ ] Dark mode toggle
- [ ] Real-time notifications
- [ ] Voice and video calls
- [ ] Message encryption indicators
- [ ] File upload progress
- [ ] Message search functionality
- [ ] User profile management
- [ ] Group chat features

## Available Scripts

- `npm start` - Start development server
- `npm build` - Build for production
- `npm test` - Run tests
- `npm eject` - Eject from Create React App

## Environment Variables

The app uses a proxy configuration in `package.json` to forward API requests to the backend server. Make sure the backend is running on port 3002.

## Contributing

1. Follow the existing code style
2. Use Material-UI components for consistency
3. Test components thoroughly
4. Update documentation as needed

## License

This project is part of the Secure Messaging App.
