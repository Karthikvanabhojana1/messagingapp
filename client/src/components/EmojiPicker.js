import React, { useState } from 'react';
import {
  Box,
  Paper,
  Grid,
  IconButton,
  Popover,
  Typography
} from '@mui/material';
import { EmojiEmotions } from '@mui/icons-material';

const EMOJI_CATEGORIES = {
  'Smileys': ['😀', '😃', '😄', '😁', '😆', '😅', '😂', '🤣', '😊', '😇', '🙂', '🙃', '😉', '😌', '😍', '🥰', '😘', '😗', '😙', '😚', '😋', '😛', '😝', '😜', '🤪', '🤨', '🧐', '🤓', '😎', '🤩', '🥳'],
  'Gestures': ['👍', '👎', '👌', '✌️', '🤞', '🤟', '🤘', '🤙', '👈', '👉', '👆', '🖕', '👇', '☝️', '👋', '🤚', '🖐️', '✋', '🖖', '👌', '🤌', '🤏', '✌️', '🤞', '🤟', '🤘', '🤙', '👈', '👉', '👆', '🖕'],
  'Hearts': ['❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔', '❣️', '💕', '💞', '💓', '💗', '💖', '💘', '💝', '💟', '♥️', '💌', '💋', '💯', '💢', '💥', '💫', '💦', '💨', '🕳️', '💬', '🗨️'],
  'Nature': ['🌸', '💮', '🏵️', '🌹', '🥀', '🌺', '🌻', '🌼', '🌷', '🌱', '🌲', '🌳', '🌴', '🌵', '🌾', '🌿', '☘️', '🍀', '🍁', '🍂', '🍃', '🌍', '🌎', '🌏', '🌑', '🌒', '🌓', '🌔', '🌕', '🌖', '🌗'],
  'Food': ['🍎', '🍐', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓', '🫐', '🍈', '🍒', '🍑', '🥭', '🍍', '🥥', '🥝', '🍅', '🥑', '🥦', '🥬', '🥒', '🌶️', '🫑', '🌽', '🥕', '🫒', '🧄', '🧅', '🥔', '🍠', '🥐'],
  'Activities': ['⚽', '🏀', '🏈', '⚾', '🥎', '🎾', '🏐', '🏉', '🥏', '🎱', '🪀', '🏓', '🏸', '🏒', '🏑', '🥍', '🏏', '🥅', '⛳', '🪁', '🏹', '🎣', '🤿', '🥊', '🥋', '🎽', '🛹', '🛷', '⛸️', '🥌', '🎿']
};

const EmojiPicker = ({ onEmojiSelect, anchorEl, onClose }) => {
  const [selectedCategory, setSelectedCategory] = useState('Smileys');

  const handleEmojiClick = (emoji) => {
    onEmojiSelect(emoji);
    onClose();
  };

  return (
    <Popover
      open={Boolean(anchorEl)}
      anchorEl={anchorEl}
      onClose={onClose}
      anchorOrigin={{
        vertical: 'top',
        horizontal: 'left',
      }}
      transformOrigin={{
        vertical: 'bottom',
        horizontal: 'left',
      }}
      PaperProps={{
        sx: {
          maxWidth: 320,
          maxHeight: 400,
          overflow: 'hidden'
        }
      }}
    >
      <Paper sx={{ p: 1 }}>
        {/* Category Tabs */}
        <Box sx={{ display: 'flex', borderBottom: 1, borderColor: 'divider', mb: 1 }}>
          {Object.keys(EMOJI_CATEGORIES).map((category) => (
            <Box
              key={category}
              onClick={() => setSelectedCategory(category)}
              sx={{
                px: 1,
                py: 0.5,
                cursor: 'pointer',
                borderBottom: selectedCategory === category ? 2 : 0,
                borderColor: 'primary.main',
                backgroundColor: selectedCategory === category ? 'action.selected' : 'transparent',
                borderRadius: 1,
                mx: 0.5,
                '&:hover': {
                  backgroundColor: 'action.hover'
                }
              }}
            >
              <Typography variant="caption">{category}</Typography>
            </Box>
          ))}
        </Box>

        {/* Emoji Grid */}
        <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
          <Grid container spacing={0.5}>
            {EMOJI_CATEGORIES[selectedCategory].map((emoji, index) => (
              <Grid item key={index}>
                <IconButton
                  size="small"
                  onClick={() => handleEmojiClick(emoji)}
                  sx={{
                    fontSize: '1.5rem',
                    width: 32,
                    height: 32,
                    '&:hover': {
                      backgroundColor: 'action.hover'
                    }
                  }}
                >
                  {emoji}
                </IconButton>
              </Grid>
            ))}
          </Grid>
        </Box>
      </Paper>
    </Popover>
  );
};

export default EmojiPicker; 