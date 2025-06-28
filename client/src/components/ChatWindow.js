import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Box,
  Typography,
  TextField,
  IconButton,
  Paper,
  Avatar,
  List,
  ListItem,
  CircularProgress,
  Alert,
  Snackbar,
  Menu,
  MenuItem
} from '@mui/material';
import {
  Send,
  EmojiEmotions,
  MoreVert,
  VideoCall,
  Phone
} from '@mui/icons-material';
import axios from 'axios';
import { useSocket } from '../context/SocketContext';
import EmojiPicker from './EmojiPicker';

const ChatWindow = ({ selectedContact, currentUser }) => {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [emojiPickerAnchor, setEmojiPickerAnchor] = useState(null);
  const [error, setError] = useState('');
  const messagesEndRef = useRef(null);
  const { socket, isConnected } = useSocket();
  const [anchorEl, setAnchorEl] = useState(null);
  const [menuMessageId, setMenuMessageId] = useState(null);

  const loadMessages = useCallback(async () => {
    if (!selectedContact) return;
    
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`/api/messages/${selectedContact.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMessages(response.data.messages || []);
    } catch (error) {
      console.error('Error loading messages:', error);
    } finally {
      setLoading(false);
    }
  }, [selectedContact]);

  useEffect(() => {
    if (selectedContact) {
      loadMessages();
    }
  }, [selectedContact, loadMessages]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Listen for new messages from Socket.IO
  useEffect(() => {
    if (!socket) {
      console.log('No socket available for message listening');
      return;
    }

    console.log('Setting up message listener');
    console.log('Socket connected:', socket.connected);
    console.log('Current selectedContact:', selectedContact?.id);

    const handleNewMessage = (message) => {
      console.log('Received new message:', message);
      console.log('Current selectedContact:', selectedContact?.id);
      console.log('Message sender_id:', message.sender_id);
      console.log('Message receiver_id:', message.receiver_id);
      console.log('Current user ID:', currentUser?.id);
      
      // Check if message is for the current conversation
      // A message is for the current conversation if it involves both the current user and the selected contact
      const isForCurrentConversation = (
        (message.sender_id === currentUser?.id && message.receiver_id === selectedContact?.id) ||
        (message.sender_id === selectedContact?.id && message.receiver_id === currentUser?.id)
      );
      
      if (isForCurrentConversation) {
        console.log('Adding message to current conversation');
        setMessages(prev => {
          // Check if message already exists to avoid duplicates
          const exists = prev.some(m => 
            m.id === message.id ||
            (m.content === message.content &&
             m.sender_id === message.sender_id &&
             m.receiver_id === message.receiver_id &&
             Math.abs(new Date(m.created_at) - new Date(message.created_at)) < 5000)
          );
          
          if (!exists) {
            console.log('Adding new message to state');
            // Add the new message and sort
            const newMessages = [...prev, message];
            return newMessages.sort((a, b) => {
              try {
                const dateA = new Date(a.created_at);
                const dateB = new Date(b.created_at);
                return dateA.getTime() - dateB.getTime();
              } catch (error) {
                return 0;
              }
            });
          } else {
            console.log('Message already exists, skipping');
            return prev;
          }
        });
      } else {
        console.log('Message not for current conversation');
      }
    };

    const handleMessageDelivered = (deliveryInfo) => {
      console.log('Message delivered:', deliveryInfo);
      setMessages(prev => 
        prev.map(m => 
          m.isPending && m.content === deliveryInfo.content 
            ? { ...m, deliveryStatus: 'delivered', isPending: false }
            : m
        )
      );
    };

    const handleMessageRead = (readInfo) => {
      console.log('Message read:', readInfo);
      setMessages(prev =>
        prev.map(m =>
          readInfo.messageIds?.includes(m.id)
            ? { ...m, isRead: true }
            : m
        )
      );
    };

    socket.on('new_message', handleNewMessage);
    socket.on('message_delivered', handleMessageDelivered);
    socket.on('message_read', handleMessageRead);

    return () => {
      console.log('Cleaning up message listener');
      socket.off('new_message', handleNewMessage);
      socket.off('message_delivered', handleMessageDelivered);
      socket.off('message_read', handleMessageRead);
    };
  }, [socket, selectedContact?.id, currentUser?.id]);

  const sendMessage = async () => {
    if (!newMessage.trim() || !selectedContact) return;

    console.log('Sending message to:', selectedContact.username);
    console.log('Message content:', newMessage);

    setSending(true);
    const messageToSend = newMessage;
    setNewMessage('');

    try {
      const token = localStorage.getItem('token');
      const messageData = {
        receiverId: selectedContact.id,
        content: messageToSend,
        messageType: 'text'
      };
      
      console.log('Sending message data:', messageData);
      
      const response = await axios.post('/api/messages', messageData, {
        headers: { Authorization: `Bearer ${token}` }
      });

      console.log('Message sent successfully:', response.data);

    } catch (error) {
      console.error('Error sending message:', error);
      console.error('Error response:', error.response?.data);
    } finally {
      setSending(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const formatTime = (timestamp) => {
    try {
      const date = new Date(timestamp);
      if (isNaN(date.getTime())) {
        console.warn('Invalid timestamp:', timestamp);
        return 'Invalid time';
      }
      return date.toLocaleTimeString([], { 
        hour: '2-digit', 
        minute: '2-digit',
        timeZone: 'UTC'
      });
    } catch (error) {
      console.error('Error formatting time:', error);
      return 'Invalid time';
    }
  };

  // Clean up pending messages that haven't been replaced after 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setMessages(prev => {
        const now = Date.now();
        const updatedMessages = prev.map(message => {
          if (message.isPending) {
            const messageTime = new Date(message.created_at).getTime();
            if (now - messageTime > 10000) { // 10 seconds
              console.log('Removing stale pending message:', message.content);
              return null; // Remove this message
            }
          }
          return message;
        }).filter(Boolean); // Remove null messages
        
        if (updatedMessages.length !== prev.length) {
          console.log('Cleaned up stale pending messages');
        }
        
        return updatedMessages;
      });
    }, 5000); // Check every 5 seconds

    return () => clearInterval(interval);
  }, []);

  // Mark messages as read when they're viewed
  const markMessagesAsRead = useCallback(async () => {
    if (!selectedContact || !currentUser) return;

    try {
      const token = localStorage.getItem('token');
      await axios.put(`/api/messages/read/${selectedContact.id}`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
    } catch (error) {
      console.error('Error marking messages as read:', error);
    }
  }, [selectedContact, currentUser]);

  // Mark messages as read when conversation is opened
  useEffect(() => {
    if (selectedContact && messages.length > 0) {
      // Mark messages as read after a short delay
      const timer = setTimeout(() => {
        markMessagesAsRead();
      }, 1000);
      
      return () => clearTimeout(timer);
    }
  }, [selectedContact, messages.length, markMessagesAsRead]);

  const handleEmojiClick = (event) => {
    setEmojiPickerAnchor(event.currentTarget);
  };

  const handleEmojiSelect = (emoji) => {
    setNewMessage(prev => prev + emoji);
  };

  const handleEmojiPickerClose = () => {
    setEmojiPickerAnchor(null);
  };

  const renderMessageContent = (message) => {
    if (message.is_deleted) {
      return (
        <Typography variant="body2" sx={{ fontStyle: 'italic', color: 'text.secondary' }}>
          This message was deleted
        </Typography>
      );
    }
    return (
      <Typography variant="body1">
        {message.content}
        {message.isPending && (
          <Typography 
            component="span" 
            variant="caption" 
            sx={{ ml: 1, opacity: 0.8 }}
          >
            (sending...)
          </Typography>
        )}
      </Typography>
    );
  };

  // Delete message handler
  const handleDeleteMessage = async (messageId) => {
    try {
      const token = localStorage.getItem('token');
      await axios.delete(`/api/messages/${messageId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      // Optimistically update UI (Socket.IO will also update)
      setMessages(prev => prev.filter(m => m.id !== messageId));
    } catch (error) {
      setError('Failed to delete message');
    }
    setAnchorEl(null);
    setMenuMessageId(null);
  };

  // Listen for message_deleted event
  useEffect(() => {
    if (!socket) return;
    const handleMessageDeleted = ({ messageId }) => {
      setMessages(prev => prev.filter(m => m.id !== messageId));
    };
    socket.on('message_deleted', handleMessageDeleted);
    return () => socket.off('message_deleted', handleMessageDeleted);
  }, [socket]);

  if (!selectedContact) {
    return (
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100%',
          backgroundColor: '#f5f5f5'
        }}
      >
        <Typography variant="h6" color="text.secondary">
          Select a contact to start chatting
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Chat Header */}
      <Paper
        elevation={1}
        sx={{
          p: 2,
          display: 'flex',
          alignItems: 'center',
          gap: 2,
          borderBottom: 1,
          borderColor: 'divider'
        }}
      >
        <Avatar>
          <Typography>{selectedContact.username?.charAt(0).toUpperCase()}</Typography>
        </Avatar>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h6">{selectedContact.username}</Typography>
          <Typography variant="body2" color="text.secondary">
            {selectedContact.is_online ? 'Online' : 'Offline'}
            {!isConnected && ' (Disconnected)'}
          </Typography>
        </Box>
        <IconButton>
          <Phone />
        </IconButton>
        <IconButton>
          <VideoCall />
        </IconButton>
        <IconButton>
          <MoreVert />
        </IconButton>
      </Paper>

      {/* Messages Area */}
      <Box
        sx={{
          flexGrow: 1,
          overflow: 'auto',
          p: 2,
          backgroundColor: '#f8f9fa'
        }}
      >
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
            <CircularProgress />
          </Box>
        ) : (
          <List sx={{ p: 0 }}>
            {(messages.slice().sort((a, b) => {
              try {
                const dateA = new Date(a.created_at);
                const dateB = new Date(b.created_at);
                
                if (isNaN(dateA.getTime()) || isNaN(dateB.getTime())) {
                  console.warn('Invalid timestamp found:', { a: a.created_at, b: b.created_at });
                  return 0;
                }
                
                return dateA.getTime() - dateB.getTime();
              } catch (error) {
                console.error('Error sorting messages:', error);
                return 0;
              }
            })).map((message) => {
              const isOwnMessage = message.sender_id === currentUser?.id;
              return (
                <ListItem
                  key={message.id}
                  sx={{
                    justifyContent: isOwnMessage ? 'flex-end' : 'flex-start',
                    px: 0
                  }}
                  onContextMenu={e => {
                    e.preventDefault();
                    setAnchorEl(e.currentTarget);
                    setMenuMessageId(message.id);
                  }}
                >
                  <Paper
                    elevation={1}
                    sx={{
                      p: 2,
                      maxWidth: '70%',
                      backgroundColor: isOwnMessage ? 'primary.main' : 'white',
                      color: isOwnMessage ? 'white' : 'text.primary',
                      borderRadius: 2,
                      opacity: message.isPending ? 0.7 : 1
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      {renderMessageContent(message)}
                      <IconButton
                        size="small"
                        onClick={e => {
                          setAnchorEl(e.currentTarget);
                          setMenuMessageId(message.id);
                        }}
                        sx={{ ml: 1, color: 'inherit' }}
                      >
                        <MoreVert fontSize="small" />
                      </IconButton>
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 0.5 }}>
                      <Typography
                        variant="caption"
                        sx={{
                          opacity: 0.7
                        }}
                      >
                        {formatTime(message.created_at)}
                      </Typography>
                      {isOwnMessage && (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          {message.isPending ? (
                            <Typography variant="caption" sx={{ opacity: 0.8 }}>
                              ⏳
                            </Typography>
                          ) : message.deliveryStatus === 'delivered' ? (
                            <Typography variant="caption" sx={{ opacity: 0.8 }}>
                              ✓
                            </Typography>
                          ) : message.isRead ? (
                            <Typography variant="caption" sx={{ opacity: 0.8 }}>
                              ✓✓
                            </Typography>
                          ) : (
                            <Typography variant="caption" sx={{ opacity: 0.8 }}>
                              ✓
                            </Typography>
                          )}
                        </Box>
                      )}
                    </Box>
                  </Paper>
                </ListItem>
              );
            })}
            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={() => { setAnchorEl(null); setMenuMessageId(null); }}
            >
              <MenuItem onClick={() => handleDeleteMessage(menuMessageId)}>Delete for Me</MenuItem>
            </Menu>
            <div ref={messagesEndRef} />
          </List>
        )}
      </Box>

      {/* Message Input */}
      <Paper
        elevation={1}
        sx={{
          p: 2,
          borderTop: 1,
          borderColor: 'divider'
        }}
      >
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-end' }}>
          <IconButton 
            size="small" 
            onClick={handleEmojiClick}
            color={emojiPickerAnchor ? 'primary' : 'default'}
          >
            <EmojiEmotions />
          </IconButton>
          <TextField
            fullWidth
            multiline
            maxRows={4}
            placeholder="Type a message..."
            value={newMessage}
            onChange={(e) => setNewMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            disabled={sending}
            sx={{ mx: 1 }}
          />
          <IconButton
            color="primary"
            onClick={sendMessage}
            disabled={!newMessage.trim() || sending}
          >
            {sending ? <CircularProgress size={20} /> : <Send />}
          </IconButton>
        </Box>

        {/* Emoji Picker */}
        <EmojiPicker
          anchorEl={emojiPickerAnchor}
          onClose={handleEmojiPickerClose}
          onEmojiSelect={handleEmojiSelect}
        />
      </Paper>

      {/* Error Snackbar */}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError('')}
      >
        <Alert onClose={() => setError('')} severity="error" sx={{ width: '100%' }}>
          {error}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ChatWindow; 