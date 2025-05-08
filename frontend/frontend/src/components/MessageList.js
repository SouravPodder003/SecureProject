// src/components/MessageList.js
import React, { useContext, useEffect, useRef } from 'react';
import { AuthContext } from '../context/AuthContext';

const MessageList = ({ messages }) => {
  const { user } = useContext(AuthContext);
  const messagesEndRef = useRef(null);

  // Auto-scroll to the bottom when new messages are added
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  if (messages.length === 0) {
    return <div className="empty-chat">No messages yet. Start the conversation!</div>;
  }

  return (
    <div className="message-list">
      {messages.map((msg, index) => (
        <div
          key={index}
          className={`message ${msg.username === user.username ? 'message-user' : 'message-other'}`}
        >
          <div className="message-content">
            <p>{msg.message}</p>
          </div>
          <div className="message-info">
            {msg.username !== user.email && <span>{msg.username}</span>}
            <span> · {new Date(msg.timestamp).toLocaleTimeString()}</span>
          </div>
        </div>
      ))}
      <div ref={messagesEndRef} />
    </div>
  );
};

export default MessageList;
