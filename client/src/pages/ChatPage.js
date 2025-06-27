import React, { useState } from 'react';
import { Box, AppBar, Toolbar, Typography, IconButton, Avatar } from '@mui/material';
import { Settings, Logout } from '@mui/icons-material';
import Sidebar from '../components/Sidebar';
import ChatWindow from '../components/ChatWindow';
import { useAuth } from '../context/AuthContext';

const ChatPage = () => {
  const [selectedContact, setSelectedContact] = useState(null);
  const { user, logout } = useAuth();

  const handleContactSelect = (contact) => {
    setSelectedContact(contact);
  };

  const handleLogout = () => {
    logout();
  };

  return (
    <Box sx={{ display: 'flex', height: '100vh' }}>
      {/* Sidebar */}
      <Sidebar
        onContactSelect={handleContactSelect}
        selectedContact={selectedContact}
      />

      {/* Main Chat Area */}
      <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
        {/* Top App Bar */}
        <AppBar position="static" elevation={1}>
          <Toolbar>
            <Typography variant="h6" sx={{ flexGrow: 1 }}>
              Secure Messaging
            </Typography>
            
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2">
                {user?.username}
              </Typography>
              <Avatar sx={{ width: 32, height: 32 }}>
                <Typography variant="body2">
                  {user?.username?.charAt(0).toUpperCase()}
                </Typography>
              </Avatar>
              <IconButton color="inherit" size="small">
                <Settings />
              </IconButton>
              <IconButton color="inherit" size="small" onClick={handleLogout}>
                <Logout />
              </IconButton>
            </Box>
          </Toolbar>
        </AppBar>

        {/* Chat Window */}
        <Box sx={{ flexGrow: 1 }}>
          <ChatWindow
            selectedContact={selectedContact}
            currentUser={user}
          />
        </Box>
      </Box>
    </Box>
  );
};

export default ChatPage; 