'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, ArrowLeft } from 'lucide-react';

export default function ForgotPasswordPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!email) {
      return;
    }

    setIsLoading(true);
    try {
      // Mock API call
      await new Promise((resolve) => setTimeout(resolve, 500));
      setSubmitted(true);
    } catch (error) {
      console.error('Error sending reset email:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4 transition-colors duration-200"
      style={{
        backgroundColor: 'var(--bg-primary)',
      }}
    >
      <div className="w-full max-w-md">
        {/* Logo Section */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div
              className="p-3 rounded-lg"
              style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-primary)',
                borderWidth: '1px',
              }}
            >
              <Shield size={40} style={{ color: '#3b82f6' }} />
            </div>
          </div>
          <h1
            className="text-3xl font-bold tracking-tight"
            style={{
              color: 'var(--text-primary)',
            }}
          >
            THREAT ENGINE
          </h1>
          <p
            className="mt-2 text-sm"
            style={{
              color: 'var(--text-secondary)',
            }}
          >
            Cloud Security Posture Management
          </p>
        </div>

        {/* Card */}
        <div
          className="rounded-lg border p-8 transition-colors duration-200"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          {submitted ? (
            <>
              {/* Success State */}
              <div className="text-center">
                <div
                  className="inline-flex items-center justify-center w-12 h-12 rounded-full mb-4"
                  style={{
                    backgroundColor: 'rgba(34, 197, 94, 0.1)',
                  }}
                >
                  <span style={{ color: '#22c55e', fontSize: '24px' }}>✓</span>
                </div>
                <h2
                  className="text-xl font-semibold mb-2"
                  style={{
                    color: 'var(--text-primary)',
                  }}
                >
                  Check Your Email
                </h2>
                <p
                  className="text-sm mb-6"
                  style={{
                    color: 'var(--text-secondary)',
                  }}
                >
                  We've sent password reset instructions to{' '}
                  <span
                    style={{
                      color: 'var(--text-primary)',
                    }}
                  >
                    {email}
                  </span>
                </p>
                <p
                  className="text-sm mb-8"
                  style={{
                    color: 'var(--text-muted)',
                  }}
                >
                  The link will expire in 24 hours.
                </p>
              </div>

              {/* Back to Login Button */}
              <button
                onClick={() => router.push('/auth/login')}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 rounded-lg transition-colors duration-200 flex items-center justify-center gap-2"
              >
                <ArrowLeft size={18} />
                Back to Sign In
              </button>
            </>
          ) : (
            <>
              {/* Form State */}
              <h2
                className="text-xl font-semibold mb-2"
                style={{
                  color: 'var(--text-primary)',
                }}
              >
                Reset Your Password
              </h2>
              <p
                className="text-sm mb-6"
                style={{
                  color: 'var(--text-secondary)',
                }}
              >
                Enter your email address and we'll send you a link to reset your password.
              </p>

              <form onSubmit={handleSubmit} className="space-y-4">
                {/* Email Input */}
                <div>
                  <label
                    htmlFor="email"
                    className="block text-sm font-medium mb-2"
                    style={{
                      color: 'var(--text-primary)',
                    }}
                  >
                    Email Address
                  </label>
                  <input
                    id="email"
                    type="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    disabled={isLoading}
                    className="w-full px-4 py-2 rounded-lg border text-sm transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    style={{
                      backgroundColor: 'var(--bg-input)',
                      borderColor: 'var(--border-secondary)',
                      color: 'var(--text-primary)',
                    }}
                  />
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={isLoading || !email}
                  className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium py-2 rounded-lg transition-colors duration-200 mt-6"
                >
                  {isLoading ? 'Sending...' : 'Send Reset Link'}
                </button>
              </form>

              {/* Back to Login Link */}
              <div className="mt-6 text-center">
                <button
                  onClick={() => router.push('/auth/login')}
                  className="text-sm hover:underline transition-colors duration-200 flex items-center justify-center gap-1 mx-auto"
                  style={{
                    color: '#3b82f6',
                  }}
                >
                  <ArrowLeft size={16} />
                  Back to Sign In
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
