// Create a new file: src/api/api.js
import axios from 'axios';
import io from 'socket.io-client';

// Base URL for all API requests
const API_BASE_URL = process.env.REACT_APP_API_URL;

// Create an axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Ensure credentials are sent with requests
  headers: {
    'Content-Type': 'application/json',
  }
});

// Add request interceptor to include auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

const connectSocket = () => {
  const token = localStorage.getItem('token');
  return io(API_BASE_URL, {
    withCredentials: true,
    transports: ['websocket', 'polling'],
    auth: {
      token: `Bearer ${token}`,
    },
    extraHeaders: {
      'Access-Control-Allow-Origin': 'http://localhost:3000',
    }
  });
};

export { api, connectSocket };
