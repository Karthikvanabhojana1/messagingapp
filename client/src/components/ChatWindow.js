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
  Modal,
  Button,
  Menu,
  MenuItem
} from '@mui/material';
import {
  Send,
  AttachFile,
  EmojiEmotions,
  MoreVert,
  VideoCall,
  Phone,
  Image,
  VideoFile,
  AudioFile,
  Description,
  Close,
  Download,
  Archive,
  Code
} from '@mui/icons-material';
import axios from 'axios';
import { useSocket } from '../context/SocketContext';
import EmojiPicker from './EmojiPicker';

const ChatWindow = ({ selectedContact, currentUser }) => {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [pendingMessages, setPendingMessages] = useState(new Set()); // Track pending messages
  const [emojiPickerAnchor, setEmojiPickerAnchor] = useState(null);
  const [error, setError] = useState('');
  const [imagePreview, setImagePreview] = useState(null);
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);
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

    console.log('Setting up message listener for contact:', selectedContact?.username);

    const handleNewMessage = (message) => {
      console.log('📨 Received new message:', message);
      
      // Only add message if it's from the current conversation
      if (message.sender_id === selectedContact?.id || 
          message.receiver_id === selectedContact?.id) {
        console.log('✅ Adding message to current conversation');
        setMessages(prev => {
          // Check if we have a pending message with the same content from the same sender
          const pendingMessage = prev.find(m => 
            m.isPending && 
            m.content === message.content &&
            m.sender_id === message.sender_id &&
            m.receiver_id === message.receiver_id
          );

          if (pendingMessage) {
            console.log('🔄 Replacing pending message with real message');
            console.log('Pending message:', pendingMessage);
            console.log('Real message:', message);
            // Replace the pending message with the real one
            const updatedMessages = prev.map(m => 
              m.id === pendingMessage.id ? { ...message, isPending: false } : m
            );
            // Sort the messages after replacement
            return updatedMessages.sort((a, b) => {
              try {
                const dateA = new Date(a.created_at);
                const dateB = new Date(b.created_at);
                return dateA.getTime() - dateB.getTime();
              } catch (error) {
                return 0;
              }
            });
          }

          // Check if message already exists to avoid duplicates
          const exists = prev.some(m => 
            !m.isPending && 
            m.content === message.content &&
            m.sender_id === message.sender_id &&
            m.receiver_id === message.receiver_id &&
            Math.abs(new Date(m.created_at) - new Date(message.created_at)) < 5000
          );
          
          if (!exists) {
            console.log('📝 Adding new message to state');
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
            console.log('⚠️ Message already exists, skipping');
            return prev;
          }
        });
      } else {
        console.log('❌ Message not for current conversation');
      }
    };

    const handleMessageDelivered = (deliveryInfo) => {
      console.log('📬 Message delivered:', deliveryInfo);
      setMessages(prev => 
        prev.map(m => 
          m.isPending && m.content === deliveryInfo.content 
            ? { ...m, deliveryStatus: 'delivered', isPending: false }
            : m
        )
      );
    };

    const handleMessageRead = (readInfo) => {
      console.log('👁️ Message read:', readInfo);
      setMessages(prev => 
        prev.map(m => 
          m.id === readInfo.messageId 
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
  }, [socket, selectedContact]);

  const sendMessage = async () => {
    if (!newMessage.trim() || !selectedContact) return;

    console.log('🚀 Sending message to:', selectedContact.username);
    console.log('📝 Message content:', newMessage);

    setSending(true);
    
    // Create a temporary message for immediate display
    const tempMessage = {
      id: `temp_${Date.now()}`,
      sender_id: currentUser.id,
      receiver_id: selectedContact.id,
      content: newMessage,
      message_type: 'text',
      created_at: new Date().toISOString(),
      is_read: false,
      isPending: true
    };

    // Add temporary message to state
    setMessages(prev => {
      const newMessages = [...prev, tempMessage];
      return newMessages.sort((a, b) => {
        try {
          const dateA = new Date(a.created_at);
          const dateB = new Date(b.created_at);
          return dateA.getTime() - dateB.getTime();
        } catch (error) {
          return 0;
        }
      });
    });
    
    // Track this message as pending
    setPendingMessages(prev => new Set(prev).add(tempMessage.id));
    
    const messageToSend = newMessage;
    setNewMessage('');

    try {
      const token = localStorage.getItem('token');
      const messageData = {
        receiverId: selectedContact.id,
        content: messageToSend,
        messageType: 'text'
      };
      
      console.log('📤 Sending message data:', messageData);
      
      const response = await axios.post('/api/messages', messageData, {
        headers: { Authorization: `Bearer ${token}` }
      });

      console.log('✅ Message sent successfully:', response.data);

      // Remove from pending messages
      setPendingMessages(prev => {
        const newSet = new Set(prev);
        newSet.delete(tempMessage.id);
        return newSet;
      });

    } catch (error) {
      console.error('❌ Error sending message:', error);
      console.error('❌ Error response:', error.response?.data);
      
      // Remove the temporary message on error
      setMessages(prev => prev.filter(m => m.id !== tempMessage.id));
      setPendingMessages(prev => {
        const newSet = new Set(prev);
        newSet.delete(tempMessage.id);
        return newSet;
      });
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
              console.log('⏰ Removing stale pending message:', message.content);
              return null; // Remove this message
            }
          }
          return message;
        }).filter(Boolean); // Remove null messages
        
        if (updatedMessages.length !== prev.length) {
          console.log('🧹 Cleaned up stale pending messages');
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

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file || !selectedContact) return;

    console.log('📎 Uploading file:', file.name, 'Size:', file.size);

    // Check file size (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
      setError('File too large. Maximum size is 10MB.');
      return;
    }

    setUploading(true);
    
    // Create a temporary message for immediate display
    const tempMessage = {
      id: `temp_${Date.now()}`,
      sender_id: currentUser.id,
      receiver_id: selectedContact.id,
      content: `Uploading ${file.name}...`,
      message_type: getMessageType(file.name),
      file_name: file.name,
      created_at: new Date().toISOString(),
      is_read: false,
      isPending: true
    };

    // Add temporary message to state
    setMessages(prev => {
      const newMessages = [...prev, tempMessage];
      return newMessages.sort((a, b) => {
        try {
          const dateA = new Date(a.created_at);
          const dateB = new Date(b.created_at);
          return dateA.getTime() - dateB.getTime();
        } catch (error) {
          return 0;
        }
      });
    });
    
    // Track this message as pending
    setPendingMessages(prev => new Set(prev).add(tempMessage.id));

    try {
      const token = localStorage.getItem('token');
      const formData = new FormData();
      formData.append('file', file);
      formData.append('receiverId', selectedContact.id);

      console.log('📤 Uploading file to server...');
      
      const response = await axios.post('/api/upload', formData, {
        headers: { 
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });

      console.log('✅ File uploaded successfully:', response.data);

      // Remove from pending messages
      setPendingMessages(prev => {
        const newSet = new Set(prev);
        newSet.delete(tempMessage.id);
        return newSet;
      });

    } catch (error) {
      console.error('❌ File upload failed:', error);
      setError(error.response?.data?.error || 'Failed to upload file');
      
      // Remove the temporary message on error
      setMessages(prev => prev.filter(m => m.id !== tempMessage.id));
      
      // Remove from pending messages
      setPendingMessages(prev => {
        const newSet = new Set(prev);
        newSet.delete(tempMessage.id);
        return newSet;
      });
    } finally {
      setUploading(false);
      // Clear the file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const getMessageType = (fileName) => {
    const ext = fileName.toLowerCase().split('.').pop();
    
    // Images
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg'].includes(ext)) {
      return 'image';
    } 
    // Videos
    else if (['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm'].includes(ext)) {
      return 'video';
    } 
    // Audio
    else if (['mp3', 'wav', 'ogg', 'm4a', 'aac', 'flac'].includes(ext)) {
      return 'audio';
    }
    // Archives
    else if (['zip', 'rar', '7z'].includes(ext)) {
      return 'archive';
    }
    // Code files
    else if (['js', 'py', 'java', 'cpp', 'c', 'php', 'sql', 'html', 'css', 'xml', 'json'].includes(ext)) {
      return 'code';
    }
    // Documents (default for PDF, DOC, XLS, PPT, TXT, etc.)
    else {
      return 'document';
    }
  };

  const getFileIcon = (messageType) => {
    switch (messageType) {
      case 'image':
        return <Image />;
      case 'video':
        return <VideoFile />;
      case 'audio':
        return <AudioFile />;
      case 'archive':
        return <Archive />;
      case 'code':
        return <Code />;
      case 'document':
        return <Description />;
      default:
        return <Description />;
    }
  };

  const getFileUrl = (content, type) => {
    if (type === 'image') {
      return content;
    } else if (type === 'video') {
      return content;
    } else if (type === 'audio') {
      return content;
    }
    return content;
  };

  const renderMessageContent = (message) => {
    if (message.is_deleted) {
      return (
        <Typography variant="body2" sx={{ fontStyle: 'italic', color: 'text.secondary' }}>
          This message was deleted
        </Typography>
      );
    }
    if (message.message_type === 'text') {
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
    } else {
      // Handle file attachments
      const isImage = message.message_type === 'image';
      const isVideo = message.message_type === 'video';
      const isAudio = message.message_type === 'audio';
      
      // Construct proper file URL
      const fileUrl = getFileUrl(message.content, message.message_type);
      
      return (
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            {getFileIcon(message.message_type)}
            <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
              {message.file_name || 'Attachment'}
            </Typography>
          </Box>
          
          {isImage && (
            <Box sx={{ width: '5rem', height: '5rem', borderRadius: 1, overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
              <img 
                src={fileUrl} 
                alt={message.file_name}
                style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }}
                onClick={() => handleImageClick(message)}
                onError={(e) => {
                  console.log('Image failed to load:', fileUrl);
                  e.target.style.display = 'none';
                  e.target.nextSibling.style.display = 'block';
                }}
              />
              <Typography 
                variant="caption" 
                sx={{ display: 'none', color: 'text.secondary', textAlign: 'center' }}
              >
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                  <Typography variant="caption">Image failed to load</Typography>
                  <Button 
                    size="small" 
                    variant="outlined"
                    onClick={() => handleDownload(fileUrl, message.file_name)}
                  >
                    Download Instead
                  </Button>
                </Box>
              </Typography>
            </Box>
          )}
          
          {isVideo && (
            <Box sx={{ maxWidth: '100%' }}>
              <video 
                controls 
                style={{ maxWidth: '100%', height: 'auto' }}
                onError={(e) => {
                  e.target.style.display = 'none';
                  e.target.nextSibling.style.display = 'block';
                }}
              >
                <source src={fileUrl} type="video/mp4" />
                Your browser does not support the video tag.
              </video>
              <Typography 
                variant="caption" 
                sx={{ display: 'none', color: 'text.secondary' }}
              >
                Video failed to load
              </Typography>
            </Box>
          )}
          
          {isAudio && (
            <Box sx={{ maxWidth: '100%' }}>
              <audio 
                controls 
                style={{ width: '100%' }}
                onError={(e) => {
                  e.target.style.display = 'none';
                  e.target.nextSibling.style.display = 'block';
                }}
              >
                <source src={fileUrl} type="audio/mpeg" />
                Your browser does not support the audio tag.
              </audio>
              <Typography 
                variant="caption" 
                sx={{ display: 'none', color: 'text.secondary' }}
              >
                Audio failed to load
              </Typography>
            </Box>
          )}
          
          {!isImage && !isVideo && !isAudio && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Description />
              <Typography variant="body2">
                <a 
                  href={fileUrl} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  style={{ color: 'inherit', textDecoration: 'none' }}
                >
                  Download {message.file_name || 'Document'}
                </a>
              </Typography>
            </Box>
          )}
          
          {message.isPending && (
            <Typography 
              component="span" 
              variant="caption" 
              sx={{ ml: 1, opacity: 0.8 }}
            >
              (uploading...)
            </Typography>
          )}
        </Box>
      );
    }
  };

  const handleImageClick = (message) => {
    let imageUrl = message.content;
    
    if (imageUrl.startsWith('/uploads/')) {
      // Old uploads format - ensure it goes to the server port
      imageUrl = imageUrl;
    } else if (imageUrl.startsWith('/api/files/')) {
      // New API format - ensure it goes to the server port
      imageUrl = imageUrl;
    } else if (!imageUrl.startsWith('http')) {
      // Any other relative URL
      imageUrl = imageUrl;
    }
    
    setImagePreview({
      src: imageUrl,
      filename: message.file_name || 'image'
    });
  };

  const handleDownload = async (url, filename) => {
    try {
      // Get the auth token for the request
      const token = localStorage.getItem('token');
      
      // Determine if this is an old uploads URL or new API URL
      const isOldUploadsUrl = url.includes('/uploads/');
      
      const headers = {};
      if (!isOldUploadsUrl) {
        // Only add auth header for new API endpoints
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      // Fetch the image as a blob
      const response = await fetch(url, {
        headers: headers
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const blob = await response.blob();
      
      // Create a blob URL and download
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      // Clean up the blob URL
      window.URL.revokeObjectURL(blobUrl);
    } catch (error) {
      console.error('Download failed:', error);
      setError('Failed to download image');
    }
  };

  // Delete message handler
  const handleDeleteMessage = async (messageId, scope = 'me') => {
    try {
      const token = localStorage.getItem('token');
      await axios.delete(`/api/messages/${messageId}?scope=${scope}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      // Optimistically update UI (Socket.IO will also update)
      if (scope === 'me') {
        setMessages(prev => prev.filter(m => m.id !== messageId));
      }
    } catch (error) {
      setError('Failed to delete message');
    }
    setAnchorEl(null);
    setMenuMessageId(null);
  };

  // Listen for message_deleted event
  useEffect(() => {
    if (!socket) return;
    const handleMessageDeleted = ({ messageId, scope }) => {
      if (scope === 'everyone') {
        setMessages(prev => prev.map(m => m.id === messageId ? { ...m, is_deleted: 1 } : m));
      } else if (scope === 'me') {
        setMessages(prev => prev.filter(m => m.id !== messageId));
      }
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
              <MenuItem onClick={() => handleDeleteMessage(menuMessageId, 'me')}>Delete for Me</MenuItem>
              {messages.find(m => m.id === menuMessageId)?.sender_id === currentUser?.id && (
                <MenuItem onClick={() => handleDeleteMessage(menuMessageId, 'everyone')}>Delete for Everyone</MenuItem>
              )}
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
          <input
            type="file"
            ref={fileInputRef}
            style={{ display: 'none' }}
            onChange={handleFileUpload}
            accept="image/*,video/*,audio/*,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.rtf,.csv,.zip,.rar,.7z,.js,.py,.java,.cpp,.c,.php,.sql,.html,.css,.xml,.json,.md,.log,.ini,.conf,.sh,.bat,.ps1,.exe,.dmg,.deb,.rpm,.apk,.ipa"
          />
          <IconButton 
            size="small" 
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
          >
            {uploading ? <CircularProgress size={20} /> : <AttachFile />}
          </IconButton>
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
            disabled={sending || uploading}
            sx={{ mx: 1 }}
          />
          <IconButton
            color="primary"
            onClick={sendMessage}
            disabled={(!newMessage.trim() && !uploading) || sending || uploading}
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

      {/* Image Preview Modal */}
      <Modal
        open={!!imagePreview}
        onClose={() => setImagePreview(null)}
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          p: 2
        }}
      >
        <Box
          sx={{
            position: 'relative',
            maxWidth: '90vw',
            maxHeight: '90vh',
            bgcolor: 'background.paper',
            borderRadius: 2,
            boxShadow: 24,
            p: 2
          }}
        >
          {/* Close Button */}
          <IconButton
            onClick={() => setImagePreview(null)}
            sx={{
              position: 'absolute',
              top: 8,
              right: 8,
              bgcolor: 'rgba(0,0,0,0.5)',
              color: 'white',
              zIndex: 1,
              '&:hover': {
                bgcolor: 'rgba(0,0,0,0.7)'
              }
            }}
          >
            <Close />
          </IconButton>

          {/* Download Button */}
          <IconButton
            onClick={() => handleDownload(imagePreview?.src, imagePreview?.filename)}
            sx={{
              position: 'absolute',
              top: 8,
              left: 8,
              bgcolor: 'rgba(0,0,0,0.5)',
              color: 'white',
              zIndex: 1,
              '&:hover': {
                bgcolor: 'rgba(0,0,0,0.7)'
              }
            }}
          >
            <Download />
          </IconButton>

          {/* Image */}
          <img
            src={imagePreview?.src}
            alt={imagePreview?.filename}
            style={{
              maxWidth: '100%',
              maxHeight: '80vh',
              display: 'block',
              borderRadius: 1
            }}
          />

          {/* Filename */}
          <Typography
            variant="body2"
            sx={{
              mt: 1,
              textAlign: 'center',
              color: 'text.secondary'
            }}
          >
            {imagePreview?.filename}
          </Typography>
        </Box>
      </Modal>

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