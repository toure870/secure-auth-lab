import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { authAPI } from '../api/auth';
import { UserResponse } from '../types/auth';

interface AuthStore {
  user: UserResponse | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  // Actions
  register: (username: string, email: string, password: string) => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshAccessToken: () => Promise<void>;
  loadUser: () => Promise<void>;
  clearError: () => void;
}

export const useAuthStore = create<AuthStore>(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      register: async (username: string, email: string, password: string) => {
        set({ isLoading: true, error: null });
        try {
          const user = await authAPI.register({ username, email, password });
          set({ user, isAuthenticated: true, isLoading: false });
        } catch (error: any) {
          const errorMessage = error.response?.data?.detail || 'Registration failed';
          set({ error: errorMessage, isLoading: false });
          throw error;
        }
      },

      login: async (email: string, password: string) => {
        set({ isLoading: true, error: null });
        try {
          const { access_token, refresh_token } = await authAPI.login({
            email,
            password,
          });
          set({
            accessToken: access_token,
            refreshToken: refresh_token,
            isAuthenticated: true,
            isLoading: false,
          });

          // Load user profile
          await get().loadUser();
        } catch (error: any) {
          const errorMessage = error.response?.data?.detail || 'Login failed';
          set({ error: errorMessage, isLoading: false, isAuthenticated: false });
          throw error;
        }
      },

      logout: async () => {
        try {
          await authAPI.logout();
        } catch (error) {
          console.error('Logout error:', error);
        } finally {
          set({
            user: null,
            accessToken: null,
            refreshToken: null,
            isAuthenticated: false,
          });
        }
      },

      refreshAccessToken: async () => {
        const { refreshToken } = get();
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }

        try {
          const { access_token } = await authAPI.refresh(refreshToken);
          set({ accessToken: access_token });
        } catch (error) {
          set({ isAuthenticated: false, accessToken: null, refreshToken: null });
          throw error;
        }
      },

      loadUser: async () => {
        try {
          const user = await authAPI.getCurrentUser();
          set({ user });
        } catch (error) {
          console.error('Failed to load user:', error);
        }
      },

      clearError: () => set({ error: null }),
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    },
  ),
);
