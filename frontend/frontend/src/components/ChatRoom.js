// src/components/ChatRoom.js
import React, { useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import MessageList from './MessageList';
import MessageInput from './MessageInput';
import { AuthContext } from '../context/AuthContext';
import { api, connectSocket } from '../api/api';

const ChatRoom = () => {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [socket, setSocket] = useState(null);
  const { user, logout } = useContext(AuthContext);  // Extract user from AuthContext
  const navigate = useNavigate();

  // Polling interval to fetch messages every 5 seconds (or adjust as needed)
  const POLL_INTERVAL = 500;

  useEffect(() => {
    const fetchMessages = async () => {
      try {
        const response = await api.get('/messages');
        // Ensure each message contains the username
        const messagesWithUser = response.data.map((message) => ({
          ...message,
          user: message.user || user.username,  // Use the logged-in username if not present
        }));
        setMessages(messagesWithUser);
      } catch (error) {
        console.error('Error fetching messages:', error);
      } finally {
        setLoading(false);
      }
    };

    const newSocket = connectSocket();
    setSocket(newSocket);

    newSocket.on('connect', () => {
      console.log('Connected to WebSocket server');
    });

    // Listen for new messages
    newSocket.on('chat_message', (message) => {
      // Include the user information in the incoming message
      setMessages((prevMessages) => [
        ...prevMessages,
        { ...message, user: message.user || user.username }, // Ensure username is set
      ]);
    });

    newSocket.on('disconnect', () => {
      console.log('Disconnected from WebSocket server');
    });

    newSocket.on('connect_error', (error) => {
      console.error('Socket.IO connection error:', error);
    });

    // Fetch messages from the server initially
    fetchMessages();

    // Polling to check for new messages every 5 seconds
    const pollingInterval = setInterval(fetchMessages, POLL_INTERVAL);

    // Clean up WebSocket connections and polling interval when the component unmounts
    return () => {
      if (newSocket) {
        newSocket.off('chat_message');
        newSocket.disconnect();
      }
      clearInterval(pollingInterval); // Clear the polling interval
    };
  }, [user.username]);  // Re-run the effect when username changes

  const handleSendMessage = async (messageText) => {
    if (!messageText.trim()) return;

    // Create a temporary message with the logged-in user's information
    const newMessage = {
      user: user.username,  // Make sure the username is included
      message: messageText,
      timestamp: new Date().toISOString(),
    };

    // Optimistically update the message list before the server response
    setMessages((prevMessages) => [...prevMessages, newMessage]);

    try {
      // Send the message to the server with the user's username
      await api.post('/messages', {
        message: messageText,
        userId: user.id
      });
      // WebSocket will automatically handle the broadcast
    } catch (error) {
      console.error('Error sending message:', error);
      // In case of error, you can optionally remove the optimistic update or show an error
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (loading) {
    return <div className="loading">Loading messages...</div>;
  }

  return (
    <div className="chat-container">
      <div className="chat-header">
        <h2>Chat Room</h2>
        <span className="username">Logged in as: <strong>{user.username}</strong></span>
        <button onClick={handleLogout} className="logout-btn">
          Logout
        </button>
      </div>
      <MessageList messages={messages} />
      <MessageInput onSendMessage={handleSendMessage} />
    </div>
  );
};

export default ChatRoom;
