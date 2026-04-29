'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { CheckCircle, ArrowLeft } from 'lucide-react';

export default function AddUserPage() {
  const router = useRouter();
  const [submitted, setSubmitted] = useState(false);
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    role: 'user',
    sendInvite: true,
  });
  const [errors, setErrors] = useState({});

  const handleChange = (field, value) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    // Clear error for this field
    if (errors[field]) {
      setErrors((prev) => ({ ...prev, [field]: '' }));
    }
  };

  const validateForm = () => {
    const newErrors = {};

    if (!formData.firstName.trim()) {
      newErrors.firstName = 'First name is required';
    }
    if (!formData.lastName.trim()) {
      newErrors.lastName = 'Last name is required';
    }
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!formData.email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      newErrors.email = 'Please enter a valid email address';
    }

    return newErrors;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const newErrors = validateForm();

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    // Mock submission
    setSubmitted(true);
    setTimeout(() => {
      router.push('/settings/users');
    }, 2000);
  };

  const handleCancel = () => {
    router.push('/settings/users');
  };

  if (submitted) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div
          className="rounded-xl p-8 border text-center max-w-md"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <div className="flex justify-center mb-4">
            <CheckCircle size={48} className="text-green-400" />
          </div>
          <h2
            className="text-2xl font-bold mb-2"
            style={{ color: 'var(--text-primary)' }}
          >
            User Invitation Sent
          </h2>
          <p
            className="text-sm mb-4"
            style={{ color: 'var(--text-tertiary)' }}
          >
            {formData.firstName} {formData.lastName} has been invited to join the platform.
          </p>
          <p
            className="text-xs mb-4"
            style={{ color: 'var(--text-muted)' }}
          >
            An invitation email will be sent to {formData.email} shortly.
          </p>
          <p
            className="text-xs"
            style={{ color: 'var(--text-muted)' }}
          >
            Redirecting to users list...
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Header */}
      <div>
        <button
          onClick={handleCancel}
          className="flex items-center gap-2 text-sm font-medium mb-4 transition-colors hover:opacity-75"
          style={{ color: 'rgb(59, 130, 246)' }}
        >
          <ArrowLeft size={16} />
          Back to Users
        </button>
        <h1
          className="text-3xl font-bold"
          style={{ color: 'var(--text-primary)' }}
        >
          Add New User
        </h1>
        <p
          className="mt-1 text-sm"
          style={{ color: 'var(--text-tertiary)' }}
        >
          Create a new user account and send an invitation
        </p>
      </div>

      {/* Form Card */}
      <div
        className="rounded-xl p-8 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* First Name */}
          <div>
            <label
              htmlFor="firstName"
              className="block text-sm font-semibold mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              First Name <span className="text-red-400">*</span>
            </label>
            <input
              id="firstName"
              type="text"
              value={formData.firstName}
              onChange={(e) => handleChange('firstName', e.target.value)}
              placeholder="John"
              className={`w-full px-4 py-2.5 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.firstName ? 'border-red-500' : ''
              }`}
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: errors.firstName
                  ? 'rgb(239, 68, 68)'
                  : 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            />
            {errors.firstName && (
              <p className="text-xs text-red-400 mt-1">{errors.firstName}</p>
            )}
          </div>

          {/* Last Name */}
          <div>
            <label
              htmlFor="lastName"
              className="block text-sm font-semibold mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              Last Name <span className="text-red-400">*</span>
            </label>
            <input
              id="lastName"
              type="text"
              value={formData.lastName}
              onChange={(e) => handleChange('lastName', e.target.value)}
              placeholder="Doe"
              className={`w-full px-4 py-2.5 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.lastName ? 'border-red-500' : ''
              }`}
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: errors.lastName
                  ? 'rgb(239, 68, 68)'
                  : 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            />
            {errors.lastName && (
              <p className="text-xs text-red-400 mt-1">{errors.lastName}</p>
            )}
          </div>

          {/* Email */}
          <div>
            <label
              htmlFor="email"
              className="block text-sm font-semibold mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              Email Address <span className="text-red-400">*</span>
            </label>
            <input
              id="email"
              type="email"
              value={formData.email}
              onChange={(e) => handleChange('email', e.target.value)}
              placeholder="john.doe@example.com"
              className={`w-full px-4 py-2.5 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.email ? 'border-red-500' : ''
              }`}
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: errors.email
                  ? 'rgb(239, 68, 68)'
                  : 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            />
            {errors.email && (
              <p className="text-xs text-red-400 mt-1">{errors.email}</p>
            )}
          </div>

          {/* Role */}
          <div>
            <label
              htmlFor="role"
              className="block text-sm font-semibold mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              Role <span className="text-red-400">*</span>
            </label>
            <select
              id="role"
              value={formData.role}
              onChange={(e) => handleChange('role', e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg border transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            >
              <option value="user">User</option>
              <option value="tenant_admin">Tenant Admin</option>
              <option value="admin">Admin</option>
              <option value="super_admin">Super Admin</option>
            </select>
            <p
              className="text-xs mt-2"
              style={{ color: 'var(--text-muted)' }}
            >
              <strong>User:</strong> Can view and manage assigned resources
              <br />
              <strong>Tenant Admin:</strong> Can manage all resources within a tenant
              <br />
              <strong>Admin:</strong> Can manage users and all tenants
              <br />
              <strong>Super Admin:</strong> Full platform access
            </p>
          </div>

          {/* Send Invite Checkbox */}
          <div className="flex items-start gap-3">
            <input
              id="sendInvite"
              type="checkbox"
              checked={formData.sendInvite}
              onChange={(e) => handleChange('sendInvite', e.target.checked)}
              className="w-4 h-4 rounded border mt-1 cursor-pointer transition-colors"
              style={{
                borderColor: 'var(--border-primary)',
                accentColor: 'rgb(59, 130, 246)',
              }}
            />
            <label
              htmlFor="sendInvite"
              className="text-sm cursor-pointer"
              style={{ color: 'var(--text-secondary)' }}
            >
              Send invitation email immediately
              <p
                className="text-xs mt-1"
                style={{ color: 'var(--text-muted)' }}
              >
                The user will receive an email with instructions to set up their account.
              </p>
            </label>
          </div>

          {/* Form Actions */}
          <div className="flex gap-3 pt-6 border-t" style={{ borderColor: 'var(--border-primary)' }}>
            <button
              type="button"
              onClick={handleCancel}
              className="flex-1 px-4 py-2.5 rounded-lg font-medium transition-colors"
              style={{
                backgroundColor: 'var(--bg-tertiary)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-primary)',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2.5 rounded-lg font-medium transition-colors text-white"
              style={{ backgroundColor: 'rgb(59, 130, 246)' }}
            >
              Send Invitation
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
