import React, { useState } from 'react';
import Navbar from '../components/Navbar';

const Setup2FAPage: React.FC = () => {
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verificationCode, setVerificationCode] = useState('');
  const [step, setStep] = useState<'setup' | 'verify' | 'complete'>('setup');

  const handleSetup2FA = async () => {
    // TODO: Call API to generate TOTP secret and QR code
    // For now, show placeholder
    setQrCode('https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=Placeholder');
    setBackupCodes(['XXXX-XXXX-XXXX', 'YYYY-YYYY-YYYY', 'ZZZZ-ZZZZ-ZZZZ']);
    setStep('verify');
  };

  const handleVerify2FA = async () => {
    // TODO: Call API to verify TOTP code
    // For now, assume success
    if (verificationCode.length === 6) {
      setStep('complete');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800">
      <Navbar />

      <main className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <h1 className="text-3xl font-bold text-white mb-8">Setup Two-Factor Authentication</h1>

        {/* Step 1: Setup */}
        {step === 'setup' && (
          <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-lg p-8">
            <div className="space-y-4">
              <h2 className="text-xl font-bold text-white">Step 1: Download Authenticator</h2>
              <p className="text-slate-400">
                Download an authenticator app on your phone (e.g., Google Authenticator, Microsoft Authenticator,
                Authy).
              </p>
              <button
                onClick={handleSetup2FA}
                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition"
              >
                Next: Scan QR Code
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Verify */}
        {step === 'verify' && (
          <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-lg p-8 space-y-6">
            <div>
              <h2 className="text-xl font-bold text-white mb-4">Step 2: Scan QR Code</h2>
              {qrCode && (
                <div className="bg-white p-4 rounded-lg w-fit mx-auto mb-4">
                  <img src={qrCode} alt="2FA QR Code" />
                </div>
              )}
            </div>

            <div>
              <h2 className="text-xl font-bold text-white mb-4">Step 3: Verify Code</h2>
              <p className="text-slate-400 mb-4">Enter the 6-digit code from your authenticator:</p>
              <input
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.slice(0, 6))}
                maxLength={6}
                placeholder="000000"
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500 text-center text-2xl tracking-widest"
              />
            </div>

            {backupCodes.length > 0 && (
              <div>
                <h2 className="text-xl font-bold text-white mb-4">Backup Codes</h2>
                <p className="text-slate-400 mb-4 text-sm">
                  Save these codes in a safe place. You can use them to access your account if you lose your
                  authenticator device.
                </p>
                <div className="bg-slate-700 border border-slate-600 rounded-lg p-4 space-y-2">
                  {backupCodes.map((code, index) => (
                    <code key={index} className="block text-white font-mono text-sm">
                      {code}
                    </code>
                  ))}
                </div>
              </div>
            )}

            <button
              onClick={handleVerify2FA}
              disabled={verificationCode.length !== 6}
              className="w-full px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition"
            >
              Verify & Enable 2FA
            </button>
          </div>
        )}

        {/* Step 3: Complete */}
        {step === 'complete' && (
          <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-lg p-8">
            <div className="text-center space-y-4">
              <div className="text-6xl">✓</div>
              <h2 className="text-2xl font-bold text-white">Two-Factor Authentication Enabled</h2>
              <p className="text-slate-400">
                Your account is now protected with 2FA. You'll need to enter a code from your authenticator app
                when logging in.
              </p>
              <button
                onClick={() => window.history.back()}
                className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition"
              >
                Back to Dashboard
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default Setup2FAPage;
