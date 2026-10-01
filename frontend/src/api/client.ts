import axios from 'axios';

const rawBase = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || '/api/v1';
const API_BASE_URL = rawBase.endsWith('/api/v1')
  ? rawBase
  : (rawBase === '/' ? '/api/v1' : `${rawBase.replace(/\/+$/, '')}/api/v1`);


export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request Interceptor: Attach JWT Bearer Token if present
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('aegis_access_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor: Handle 401 Unauthorized globally
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('aegis_access_token');
      // Option to redirect to login if needed
    }
    return Promise.reject(error);
  }
);
