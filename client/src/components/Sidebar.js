import React, { useState, useEffect } from 'react';
import {
  Box,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Avatar,
  Typography,
  Divider,
  IconButton,
  Badge,
  Tabs,
  Tab,
  CircularProgress
} from '@mui/material';
import {
  Person,
  Group,
  Chat,
  VideoCall,
  Phone,
  MoreVert
} from '@mui/icons-material';
import axios from 'axios';

const Sidebar = ({ onContactSelect, selectedContact }) => {
  const [contacts, setContacts] = useState([]);
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(0);

  useEffect(() => {
    loadContacts();
    loadGroups();
  }, []);

  const loadContacts = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/users', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setContacts(response.data.users || []);
    } catch (error) {
      console.error('Error loading contacts:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadGroups = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/groups', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setGroups(response.data.groups || []);
    } catch (error) {
      console.error('Error loading groups:', error);
    }
  };

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const handleContactClick = (contact) => {
    onContactSelect(contact);
  };

  if (loading) {
    return (
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100%'
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ width: 320, borderRight: 1, borderColor: 'divider' }}>
      {/* Header */}
      <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
        <Typography variant="h6">Chats</Typography>
      </Box>

      {/* Tabs */}
      <Tabs value={activeTab} onChange={handleTabChange} centered>
        <Tab label="Contacts" />
        <Tab label="Groups" />
      </Tabs>

      <Divider />

      {/* Contact/Group List */}
      <List sx={{ p: 0 }}>
        {activeTab === 0 ? (
          // Contacts Tab
          contacts.map((contact) => (
            <ListItem
              key={contact.id}
              button="true"
              selected={selectedContact?.id === contact.id}
              onClick={() => handleContactClick(contact)}
              sx={{
                '&:hover': { backgroundColor: 'action.hover' },
                '&.Mui-selected': { backgroundColor: 'primary.light' }
              }}
            >
              <ListItemAvatar>
                <Badge
                  color="success"
                  variant="dot"
                  invisible={!contact.is_online}
                >
                  <Avatar>
                    <Person />
                  </Avatar>
                </Badge>
              </ListItemAvatar>
              <ListItemText
                primary={contact.username}
                secondary={contact.is_online ? 'Online' : 'Offline'}
              />
              <IconButton size="small">
                <MoreVert />
              </IconButton>
            </ListItem>
          ))
        ) : (
          // Groups Tab
          groups.map((group) => (
            <ListItem
              key={group.id}
              button
              onClick={() => handleContactClick(group)}
            >
              <ListItemAvatar>
                <Avatar>
                  <Group />
                </Avatar>
              </ListItemAvatar>
              <ListItemText
                primary={group.name}
                secondary={`${group.member_count || 0} members`}
              />
            </ListItem>
          ))
        )}
      </List>

      {/* Quick Actions */}
      <Box sx={{ p: 2, borderTop: 1, borderColor: 'divider' }}>
        <Typography variant="subtitle2" gutterBottom>
          Quick Actions
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <IconButton size="small" color="primary">
            <Chat />
          </IconButton>
          <IconButton size="small" color="primary">
            <VideoCall />
          </IconButton>
          <IconButton size="small" color="primary">
            <Phone />
          </IconButton>
        </Box>
      </Box>
    </Box>
  );
};

export default Sidebar; 