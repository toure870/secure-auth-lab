export interface UserResponse {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_verified: boolean;
  created_at: string;
  last_login: string | null;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthError {
  detail: string;
  status_code: number;
}
