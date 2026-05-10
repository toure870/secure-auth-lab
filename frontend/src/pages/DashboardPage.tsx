import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Navbar from '../components/Navbar';
import { useAuthStore } from '../store/authStore';

const DashboardPage: React.FC = () => {
  const { user, loadUser } = useAuthStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (!user) {
      loadUser();
    }
  }, [user, loadUser]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800">
      <Navbar />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Welcome Section */}
        <div className="mb-12">
          <h1 className="text-4xl font-bold text-white mb-2">
            Welcome, {user?.username}! 👋
          </h1>
          <p className="text-slate-400">
            You are securely authenticated on SecureAuthLab
          </p>
        </div>

        {/* Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* User Info Card */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 shadow-lg">
            <h2 className="text-xl font-bold text-white mb-4">👤 Account Info</h2>
            <div className="space-y-3">
              <div>
                <p className="text-slate-400 text-sm">Username</p>
                <p className="text-white font-semibold">{user?.username}</p>
              </div>
              <div>
                <p className="text-slate-400 text-sm">Email</p>
                <p className="text-white font-semibold">{user?.email}</p>
              </div>
              <div>
                <p className="text-slate-400 text-sm">Account Status</p>
                <p className="text-green-400 font-semibold">
                  {user?.is_active ? '✓ Active' : '✗ Inactive'}
                </p>
              </div>
              <div>
                <p className="text-slate-400 text-sm">Verified</p>
                <p className={user?.is_verified ? 'text-green-400 font-semibold' : 'text-yellow-400 font-semibold'}>
                  {user?.is_verified ? '✓ Yes' : '✗ No'}
                </p>
              </div>
            </div>
          </div>

          {/* Security Card */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 shadow-lg">
            <h2 className="text-xl font-bold text-white mb-4">🔒 Security</h2>
            <div className="space-y-3">
              <button
                onClick={() => navigate('/profile')}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 rounded-lg transition"
              >
                Change Password
              </button>
              <button
                onClick={() => navigate('/setup-2fa')}
                className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 rounded-lg transition"
              >
                Setup 2FA
              </button>
            </div>
          </div>

          {/* Security Features Card */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 shadow-lg">
            <h2 className="text-xl font-bold text-white mb-4">✨ Features</h2>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li>✓ Bcrypt Password Hashing</li>
              <li>✓ JWT Authentication</li>
              <li>✓ Rate Limiting</li>
              <li>✓ Brute Force Protection</li>
              <li>✓ Audit Logging</li>
              <li>✓ 2FA Support</li>
            </ul>
          </div>
        </div>

        {/* Security Lab Notice */}
        <div className="mt-12 bg-blue-900 border border-blue-700 rounded-lg p-6">
          <h3 className="text-lg font-bold text-blue-200 mb-2">🔬 Security Lab</h3>
          <p className="text-blue-100">
            This dashboard is part of the SecureAuthLab - an educational platform to understand modern
            security practices. All authentication mechanisms are designed to protect against common attacks:
            SQL Injection, XSS, CSRF, Brute Force, and more.
          </p>
        </div>
      </main>
    </div>
  );
};

export default DashboardPage;
