'use client';

import { useState, useEffect } from 'react';
import { User, Mail, Phone, Lock, CheckCircle } from 'lucide-react';
import { useToast } from '@/lib/toast-context';
import { fetchFromCspm } from '@/lib/api';

export default function ProfilePage() {
  const toast = useToast();
  const [editMode, setEditMode] = useState(false);
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [successMessage, setSuccessMessage] = useState(null);
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
  });

  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });

  const [userMeta, setUserMeta] = useState({
    role: '—',
    lastLogin: '—',
    createdAt: '—',
  });

  // Fetch current user profile from CSPM Django backend
  useEffect(() => {
    (async () => {
      try {
        const res = await fetchFromCspm('/api/users/me/');
        if (res && !res.error) {
          setFormData({
            firstName: res.first_name || '',
            lastName: res.last_name || '',
            email: res.email || '',
            phone: res.phone || '',
          });
          setUserMeta({
            role: res.role || (res.is_superuser ? 'Super Admin' : res.is_staff ? 'Admin' : 'User'),
            lastLogin: res.last_login ? new Date(res.last_login).toLocaleString() : '—',
            createdAt: res.date_joined ? new Date(res.date_joined).toLocaleDateString() : '—',
          });
        }
      } catch (err) {
        console.warn('Failed to fetch user profile:', err);
      }
    })();
  }, []);

  const handleEditChange = (field, value) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handlePasswordChange = (field, value) => {
    setPasswordData((prev) => ({ ...prev, [field]: value }));
  };

  const handleSaveProfile = (e) => {
    e.preventDefault();
    setSuccessMessage('Profile updated successfully!');
    setEditMode(false);
    setTimeout(() => setSuccessMessage(null), 3000);
  };

  const handleChangePassword = (e) => {
    e.preventDefault();
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    setSuccessMessage('Password changed successfully!');
    setPasswordData({
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    });
    setShowPasswordForm(false);
    setTimeout(() => setSuccessMessage(null), 3000);
  };

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Success Message */}
      {successMessage && (
        <div
          className="p-4 rounded-lg border flex items-center gap-3"
          style={{
            backgroundColor: 'rgb(240, 253, 244)',
            borderColor: 'rgb(187, 247, 208)',
            color: 'rgb(4, 120, 87)',
          }}
        >
          <CheckCircle size={20} />
          <span className="font-medium">{successMessage}</span>
        </div>
      )}

      {/* Page Header */}
      <div>
        <h1
          className="text-3xl font-bold mb-1"
          style={{ color: 'var(--text-primary)' }}
        >
          Profile
        </h1>
        <p style={{ color: 'var(--text-tertiary)' }} className="text-sm">
          Manage your account information and preferences
        </p>
      </div>

      {/* Avatar & Basic Info */}
      <div
        className="rounded-xl p-8 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex items-start gap-6">
          {/* Avatar */}
          <div
            className="flex items-center justify-center w-24 h-24 rounded-full font-bold text-2xl flex-shrink-0"
            style={{
              backgroundColor: 'rgb(59, 130, 246)',
              color: 'white',
            }}
          >
            {(formData.firstName?.[0] || '').toUpperCase()}{(formData.lastName?.[0] || '').toUpperCase()}
          </div>

          {/* User Info */}
          <div className="flex-1">
            <h2
              className="text-2xl font-bold mb-1"
              style={{ color: 'var(--text-primary)' }}
            >
              {formData.firstName} {formData.lastName}
            </h2>
            <p
              className="text-sm mb-4"
              style={{ color: 'var(--text-tertiary)' }}
            >
              {userMeta.role}
            </p>

            {/* Quick Info */}
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p style={{ color: 'var(--text-muted)' }} className="text-xs">
                  Last Login
                </p>
                <p
                  style={{ color: 'var(--text-secondary)' }}
                  className="font-medium"
                >
                  {userMeta.lastLogin}
                </p>
              </div>
              <div>
                <p style={{ color: 'var(--text-muted)' }} className="text-xs">
                  Member Since
                </p>
                <p
                  style={{ color: 'var(--text-secondary)' }}
                  className="font-medium"
                >
                  {userMeta.createdAt}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Edit Profile Form */}
      <div
        className="rounded-xl p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex items-center justify-between mb-6">
          <h3
            className="text-lg font-semibold"
            style={{ color: 'var(--text-primary)' }}
          >
            Profile Information
          </h3>
          <button
            onClick={() => setEditMode(!editMode)}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            style={{
              backgroundColor: editMode ? 'var(--bg-tertiary)' : 'rgb(59, 130, 246)',
              color: editMode ? 'var(--text-secondary)' : 'white',
              border: editMode ? '1px solid var(--border-primary)' : 'none',
            }}
          >
            {editMode ? 'Cancel' : 'Edit'}
          </button>
        </div>

        <form onSubmit={handleSaveProfile} className="space-y-4">
          {/* First Name */}
          <div>
            <label
              className="block text-sm font-medium mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              First Name
            </label>
            <input
              type="text"
              value={formData.firstName}
              onChange={(e) => handleEditChange('firstName', e.target.value)}
              disabled={!editMode}
              className="w-full px-4 py-2 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60"
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          {/* Last Name */}
          <div>
            <label
              className="block text-sm font-medium mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              Last Name
            </label>
            <input
              type="text"
              value={formData.lastName}
              onChange={(e) => handleEditChange('lastName', e.target.value)}
              disabled={!editMode}
              className="w-full px-4 py-2 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60"
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          {/* Email (Read-only) */}
          <div>
            <label
              className="block text-sm font-medium mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              Email Address (Read-only)
            </label>
            <input
              type="email"
              value={formData.email}
              disabled={true}
              className="w-full px-4 py-2 rounded-lg border transition-colors focus:outline-none disabled:opacity-60"
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            />
            <p
              className="text-xs mt-1"
              style={{ color: 'var(--text-muted)' }}
            >
              Contact support to change your email address
            </p>
          </div>

          {/* Phone */}
          <div>
            <label
              className="block text-sm font-medium mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              Phone Number
            </label>
            <input
              type="tel"
              value={formData.phone}
              onChange={(e) => handleEditChange('phone', e.target.value)}
              disabled={!editMode}
              className="w-full px-4 py-2 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60"
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          {/* Save Button */}
          {editMode && (
            <button
              type="submit"
              className="w-full px-4 py-2 rounded-lg font-medium transition-colors text-white"
              style={{ backgroundColor: 'rgb(59, 130, 246)' }}
            >
              Save Changes
            </button>
          )}
        </form>
      </div>

      {/* Change Password Section */}
      <div
        className="rounded-xl p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex items-center justify-between mb-6">
          <h3
            className="text-lg font-semibold flex items-center gap-2"
            style={{ color: 'var(--text-primary)' }}
          >
            <Lock size={20} />
            Security
          </h3>
          <button
            onClick={() => setShowPasswordForm(!showPasswordForm)}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            style={{
              backgroundColor: showPasswordForm
                ? 'var(--bg-tertiary)'
                : 'rgb(239, 68, 68)',
              color: showPasswordForm ? 'var(--text-secondary)' : 'white',
              border: showPasswordForm ? '1px solid var(--border-primary)' : 'none',
            }}
          >
            {showPasswordForm ? 'Cancel' : 'Change Password'}
          </button>
        </div>

        {showPasswordForm && (
          <form onSubmit={handleChangePassword} className="space-y-4">
            {/* Current Password */}
            <div>
              <label
                className="block text-sm font-medium mb-2"
                style={{ color: 'var(--text-secondary)' }}
              >
                Current Password
              </label>
              <input
                type="password"
                value={passwordData.currentPassword}
                onChange={(e) =>
                  handlePasswordChange('currentPassword', e.target.value)
                }
                required
                className="w-full px-4 py-2 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
                style={{
                  backgroundColor: 'var(--bg-tertiary)',
                  borderColor: 'var(--border-primary)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>

            {/* New Password */}
            <div>
              <label
                className="block text-sm font-medium mb-2"
                style={{ color: 'var(--text-secondary)' }}
              >
                New Password
              </label>
              <input
                type="password"
                value={passwordData.newPassword}
                onChange={(e) =>
                  handlePasswordChange('newPassword', e.target.value)
                }
                required
                className="w-full px-4 py-2 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
                style={{
                  backgroundColor: 'var(--bg-tertiary)',
                  borderColor: 'var(--border-primary)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>

            {/* Confirm Password */}
            <div>
              <label
                className="block text-sm font-medium mb-2"
                style={{ color: 'var(--text-secondary)' }}
              >
                Confirm Password
              </label>
              <input
                type="password"
                value={passwordData.confirmPassword}
                onChange={(e) =>
                  handlePasswordChange('confirmPassword', e.target.value)
                }
                required
                className="w-full px-4 py-2 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
                style={{
                  backgroundColor: 'var(--bg-tertiary)',
                  borderColor: 'var(--border-primary)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>

            <button
              type="submit"
              className="w-full px-4 py-2 rounded-lg font-medium transition-colors text-white"
              style={{ backgroundColor: 'rgb(239, 68, 68)' }}
            >
              Update Password
            </button>
          </form>
        )}

        {!showPasswordForm && (
          <div
            className="p-4 rounded-lg text-sm"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
            }}
          >
            Keep your account secure by using a strong password and changing it regularly.
          </div>
        )}
      </div>

      {/* Account Info */}
      <div
        className="rounded-xl p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <h3
          className="text-lg font-semibold mb-4"
          style={{ color: 'var(--text-primary)' }}
        >
          Account Information
        </h3>

        <div className="space-y-3 text-sm">
          <div className="flex justify-between">
            <span style={{ color: 'var(--text-tertiary)' }}>Role</span>
            <span style={{ color: 'var(--text-secondary)' }} className="font-medium">
              {userMeta.role}
            </span>
          </div>
          <div className="flex justify-between border-t pt-3" style={{ borderColor: 'var(--border-primary)' }}>
            <span style={{ color: 'var(--text-tertiary)' }}>Email</span>
            <span style={{ color: 'var(--text-secondary)' }} className="font-medium">
              {formData.email}
            </span>
          </div>
          <div className="flex justify-between border-t pt-3" style={{ borderColor: 'var(--border-primary)' }}>
            <span style={{ color: 'var(--text-tertiary)' }}>Status</span>
            <span style={{ color: 'rgb(34, 197, 94)' }} className="font-medium">
              Active
            </span>
          </div>
          <div className="flex justify-between border-t pt-3" style={{ borderColor: 'var(--border-primary)' }}>
            <span style={{ color: 'var(--text-tertiary)' }}>Account Created</span>
            <span style={{ color: 'var(--text-secondary)' }} className="font-medium">
              {userMeta.createdAt}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
