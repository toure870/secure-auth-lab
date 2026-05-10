import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';

const Navbar: React.FC = () => {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <nav className="bg-slate-900 border-b border-slate-700 shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <div className="flex items-center space-x-2">
            <div className="h-8 w-8 bg-blue-500 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold">🔐</span>
            </div>
            <span className="text-white font-bold text-lg">SecureAuthLab</span>
          </div>

          {/* Menu */}
          <div className="flex items-center space-x-4">
            {user && (
              <>
                <div className="text-slate-300 text-sm">
                  Welcome, <span className="font-semibold text-white">{user.username}</span>
                </div>
                <button
                  onClick={() => navigate('/profile')}
                  className="px-4 py-2 text-slate-300 hover:text-white transition"
                >
                  Profile
                </button>
                <button
                  onClick={handleLogout}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition"
                >
                  Logout
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
