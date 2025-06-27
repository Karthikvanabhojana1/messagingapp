import React, { createContext, useContext, useEffect, useState } from 'react';
import io from 'socket.io-client';
import { useAuth } from './AuthContext';

const SocketContext = createContext();

export const useSocket = () => {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
};

export const SocketProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState(null);
  const { user, token } = useAuth();

  useEffect(() => {
    if (token && user) {
      console.log('Attempting to connect to Socket.IO server...');
      
      // Connect to Socket.IO server
      const newSocket = io('/', {
        auth: {
          token: token
        },
        transports: ['websocket', 'polling'],
        timeout: 10000
      });

      newSocket.on('connect', () => {
        console.log('✅ Connected to Socket.IO server');
        setIsConnected(true);
        setConnectionError(null);
      });

      newSocket.on('disconnect', (reason) => {
        console.log('❌ Disconnected from Socket.IO server:', reason);
        setIsConnected(false);
      });

      newSocket.on('connect_error', (error) => {
        console.error('❌ Socket connection error:', error);
        setIsConnected(false);
        setConnectionError(error.message);
      });

      newSocket.on('error', (error) => {
        console.error('❌ Socket error:', error);
        setIsConnected(false);
        setConnectionError(error.message);
      });

      setSocket(newSocket);

      return () => {
        console.log('Cleaning up Socket.IO connection...');
        newSocket.close();
      };
    } else {
      console.log('No token or user, skipping Socket.IO connection');
    }
  }, [token, user]);

  const value = {
    socket,
    isConnected,
    connectionError
  };

  return (
    <SocketContext.Provider value={value}>
      {children}
    </SocketContext.Provider>
  );
}; 