import api from '../api/client';
import { UserResponse, LoginRequest, RegisterRequest, TokenResponse } from '../types/auth';

export const authAPI = {
  register: async (data: RegisterRequest) => {
    const response = await api.post<UserResponse>('/api/auth/register', data);
    return response.data;
  },

  login: async (data: LoginRequest) => {
    const response = await api.post<TokenResponse>('/api/auth/login', data);
    return response.data;
  },

  refresh: async (refreshToken: string) => {
    const response = await api.post<TokenResponse>('/api/auth/refresh', {
      refresh_token: refreshToken,
    });
    return response.data;
  },

  logout: async () => {
    await api.post('/api/auth/logout');
  },

  getCurrentUser: async () => {
    const response = await api.get<UserResponse>('/api/auth/me');
    return response.data;
  },
};
