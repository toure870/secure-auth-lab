import React from 'react';
import Navbar from '../components/Navbar';
import { useAuthStore } from '../store/authStore';

const ProfilePage: React.FC = () => {
  const { user } = useAuthStore();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800">
      <Navbar />

      <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <h1 className="text-3xl font-bold text-white mb-8">User Profile</h1>

        {/* Profile Card */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-lg p-8 space-y-6">
          {/* Basic Info */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Account Information</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  Username
                </label>
                <input
                  type="text"
                  value={user?.username || ''}
                  disabled
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white opacity-50 cursor-not-allowed"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  Email
                </label>
                <input
                  type="email"
                  value={user?.email || ''}
                  disabled
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white opacity-50 cursor-not-allowed"
                />
              </div>
            </div>
          </div>

          {/* Divider */}
          <div className="border-t border-slate-700"></div>

          {/* Change Password */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Change Password</h2>
            <p className="text-slate-400 mb-4 text-sm">
              This feature is coming soon. Update your password through the secure endpoint.
            </p>
            <button
              disabled
              className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition"
            >
              Change Password (Coming Soon)
            </button>
          </div>

          {/* Divider */}
          <div className="border-t border-slate-700"></div>

          {/* Account Dates */}
          <div>
            <h2 className="text-xl font-bold text-white mb-4">Account History</h2>
            <div className="space-y-3">
              <div>
                <p className="text-slate-400 text-sm">Created At</p>
                <p className="text-white">
                  {user?.created_at
                    ? new Date(user.created_at).toLocaleString()
                    : 'N/A'}
                </p>
              </div>
              <div>
                <p className="text-slate-400 text-sm">Last Login</p>
                <p className="text-white">
                  {user?.last_login
                    ? new Date(user.last_login).toLocaleString()
                    : 'N/A'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default ProfilePage;
