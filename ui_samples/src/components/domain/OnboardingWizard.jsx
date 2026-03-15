'use client';

import { useState } from 'react';
import { postToEngine } from '@/lib/api';
import { CLOUD_PROVIDERS } from '@/lib/constants';
import { useToast } from '@/lib/toast-context';

/**
 * OnboardingWizard Component
 * 3-step wizard for onboarding cloud accounts
 * Step 1: Select Cloud Provider and Auth Method
 * Step 2: Enter Credentials
 * Step 3: Validation Result
 *
 * @param {Object} props
 * @param {Function} props.onComplete - Callback with account data on completion
 * @param {Function} props.onCancel - Callback when wizard is cancelled
 * @returns {JSX.Element}
 */
export default function OnboardingWizard({ onComplete = () => {}, onCancel = () => {} }) {
  const toast = useToast();
  const [currentStep, setCurrentStep] = useState(1);
  const [provider, setProvider] = useState('');
  const [authMethod, setAuthMethod] = useState('');
  const [credentials, setCredentials] = useState({});
  const [validationStatus, setValidationStatus] = useState('idle'); // idle | validating | success | failed
  const [validationMessage, setValidationMessage] = useState('');
  const [validationError, setValidationError] = useState('');

  const handleProviderSelect = (selectedProvider) => {
    setProvider(selectedProvider);
    setAuthMethod('');
  };

  const handleAuthMethodSelect = (method) => {
    setAuthMethod(method);
  };

  const handleCredentialChange = (field, value) => {
    setCredentials(prev => ({ ...prev, [field]: value }));
  };

  const handleNext = async () => {
    if (currentStep === 1) {
      if (!provider || !authMethod) {
        toast.error('Please select both provider and auth method');
        return;
      }
      setCurrentStep(2);
    } else if (currentStep === 2) {
      // Validate credentials
      const requiredFields = getRequiredFields();
      const isEmpty = requiredFields.some(field => !credentials[field]?.trim());
      if (isEmpty) {
        toast.error('Please fill in all required fields');
        return;
      }
      setCurrentStep(3);
      await validateCredentials();
    }
  };

  const handleBack = () => {
    if (currentStep > 1) setCurrentStep(currentStep - 1);
  };

  const validateCredentials = async () => {
    setValidationStatus('validating');
    setValidationMessage('Validating credentials...');

    try {
      // First create a temporary account record to validate against
      const createResult = await postToEngine('onboarding', '/api/v1/accounts', {
        provider,
        auth_method: authMethod,
      });

      if (!createResult || !createResult.account_id) {
        throw new Error('Failed to create account record');
      }

      // Store and validate credentials
      try {
        await postToEngine('onboarding', `/api/v1/accounts/${createResult.account_id}/credentials`, credentials);

        const validateResult = await postToEngine('onboarding', `/api/v1/accounts/${createResult.account_id}/validate-credentials`, {});

        if (validateResult && validateResult.valid === true) {
          setValidationStatus('success');
          setValidationMessage('Account successfully validated');
        } else {
          setValidationStatus('failed');
          setValidationError(validateResult?.message || 'Failed to authenticate with provided credentials');
        }
      } catch (credError) {
        setValidationStatus('failed');
        setValidationError(credError.message || 'Failed to validate credentials');
      }
    } catch (error) {
      setValidationStatus('failed');
      setValidationError(error.message || 'Validation failed');
    }
  };

  const handleSaveAccount = () => {
    const accountData = {
      provider,
      authMethod,
      credentials,
      timestamp: new Date().toISOString()
    };
    onComplete(accountData);
  };

  const getRequiredFields = () => {
    if (provider === 'aws' && authMethod === 'role_arn') {
      return ['account_id', 'role_arn', 'external_id'];
    } else if (provider === 'aws' && authMethod === 'access_keys') {
      return ['access_key_id', 'secret_access_key'];
    } else if (provider === 'azure') {
      return ['subscription_id', 'tenant_id', 'client_id', 'client_secret'];
    } else if (provider === 'gcp') {
      return ['project_id', 'service_account_key'];
    } else if (provider === 'oci') {
      return ['tenancy_ocid', 'user_ocid', 'fingerprint', 'private_key'];
    }
    return [];
  };

  const authMethodOptions = {
    aws: [
      { value: 'role_arn', label: 'Role ARN' },
      { value: 'access_keys', label: 'Access Keys' }
    ],
    azure: [{ value: 'spn', label: 'Service Principal' }],
    gcp: [{ value: 'service_account', label: 'Service Account' }],
    oci: [{ value: 'api_key', label: 'API Key' }]
  };

  const renderStep = () => {
    switch (currentStep) {
      case 1:
        return <Step1 provider={provider} authMethod={authMethod} onProviderSelect={handleProviderSelect} onAuthMethodSelect={handleAuthMethodSelect} authMethodOptions={authMethodOptions} />;
      case 2:
        return <Step2 provider={provider} authMethod={authMethod} credentials={credentials} onCredentialChange={handleCredentialChange} getRequiredFields={getRequiredFields} />;
      case 3:
        return <Step3 validationStatus={validationStatus} validationMessage={validationMessage} validationError={validationError} provider={provider} credentials={credentials} />;
      default:
        return null;
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
      <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="rounded-xl border w-full max-w-2xl shadow-2xl transition-colors duration-200">
        {/* Header */}
        <div style={{ backgroundColor: 'var(--bg-tertiary)', borderBottomColor: 'var(--border-primary)' }} className="rounded-t-xl px-6 py-4 border-b transition-colors duration-200">
          <h2 style={{ color: 'var(--text-primary)' }} className="text-lg font-semibold">
            Cloud Account Onboarding
          </h2>
        </div>

        {/* Step Indicator */}
        <div style={{ borderBottomColor: 'var(--border-primary)' }} className="px-6 py-6 border-b transition-colors duration-200">
          <div className="flex items-center justify-center gap-4">
            {[1, 2, 3].map((step) => (
              <div key={step} className="flex items-center gap-4">
                <div
                  className={`w-10 h-10 rounded-full font-semibold flex items-center justify-center transition-all ${
                    step < currentStep
                      ? 'bg-green-500 text-white'
                      : step === currentStep
                        ? 'bg-blue-500 text-white ring-2 ring-blue-400 ring-offset-2'
                        : 'bg-slate-700 text-slate-400'
                  }`}
                >
                  {step < currentStep ? '✓' : step}
                </div>
                <div className="hidden sm:block">
                  <p style={{ color: 'var(--text-tertiary)' }} className="text-xs font-medium">
                    Step {step}
                  </p>
                  <p style={{ color: 'var(--text-primary)' }} className="text-sm font-medium">
                    {step === 1
                      ? 'Select Provider'
                      : step === 2
                        ? 'Enter Credentials'
                        : 'Validate'}
                  </p>
                </div>
                {step < 3 && (
                  <div className="hidden md:block w-12 h-1 bg-slate-700" />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Step Content */}
        <div className="px-6 py-8">
          {renderStep()}
        </div>

        {/* Footer Buttons */}
        <div style={{ borderTopColor: 'var(--border-primary)' }} className="px-6 py-4 border-t flex justify-between gap-3 transition-colors duration-200">
          <div className="flex gap-3">
            <button
              onClick={onCancel}
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
              className="px-4 py-2 rounded-lg font-medium text-sm hover:opacity-75 transition-colors duration-200"
            >
              Cancel
            </button>
            {currentStep > 1 && (
              <button
                onClick={handleBack}
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
                className="px-4 py-2 rounded-lg font-medium text-sm hover:opacity-75 transition-colors duration-200"
              >
                Back
              </button>
            )}
          </div>
          <div className="flex gap-3">
            {currentStep < 3 && (
              <button
                onClick={handleNext}
                className="px-6 py-2 rounded-lg bg-blue-600 text-white font-medium text-sm hover:bg-blue-700 transition-colors"
              >
                Next
              </button>
            )}
            {currentStep === 3 && validationStatus === 'success' && (
              <button
                onClick={handleSaveAccount}
                className="px-6 py-2 rounded-lg bg-green-600 text-white font-medium text-sm hover:bg-green-700 transition-colors"
              >
                Save Account
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Step 1: Provider and Auth Method Selection
 */
function Step1({ provider, authMethod, onProviderSelect, onAuthMethodSelect, authMethodOptions }) {
  return (
    <div className="space-y-6">
      <div>
        <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-4">
          Select Cloud Provider
        </label>
        <div className="grid grid-cols-2 gap-3">
          {Object.entries(CLOUD_PROVIDERS).map(([key, value]) => (
            <button
              key={key}
              onClick={() => onProviderSelect(key)}
              style={provider === key ? {} : { borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}
              className={`p-4 rounded-lg border-2 text-left transition-all ${
                provider === key
                  ? 'border-blue-500 bg-blue-500/10'
                  : 'hover:opacity-75'
              }`}
            >
              <p style={{ color: 'var(--text-primary)' }} className="font-medium">{value.name}</p>
              <p style={{ color: 'var(--text-tertiary)' }} className="text-xs mt-1">
                {key === 'aws' && 'Amazon Web Services'}
                {key === 'azure' && 'Microsoft Azure'}
                {key === 'gcp' && 'Google Cloud Platform'}
                {key === 'oci' && 'Oracle Cloud Infrastructure'}
              </p>
            </button>
          ))}
        </div>
      </div>

      {provider && (
        <div>
          <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-4">
            Authentication Method
          </label>
          <div className="grid grid-cols-1 gap-3">
            {authMethodOptions[provider]?.map((method) => (
              <button
                key={method.value}
                onClick={() => onAuthMethodSelect(method.value)}
                style={authMethod === method.value ? {} : { borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-tertiary)' }}
                className={`p-4 rounded-lg border-2 text-left transition-all ${
                  authMethod === method.value
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'hover:opacity-75'
                }`}
              >
                <p style={{ color: 'var(--text-primary)' }} className="font-medium">{method.label}</p>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Step 2: Credential Input
 */
function Step2({ provider, authMethod, credentials, onCredentialChange, getRequiredFields }) {
  const fields = getRequiredFields();
  const fieldLabels = {
    account_id: 'AWS Account ID',
    role_arn: 'Role ARN',
    external_id: 'External ID',
    access_key_id: 'Access Key ID',
    secret_access_key: 'Secret Access Key',
    subscription_id: 'Subscription ID',
    tenant_id: 'Tenant ID',
    client_id: 'Client ID',
    client_secret: 'Client Secret',
    project_id: 'Project ID',
    service_account_key: 'Service Account Key',
    tenancy_ocid: 'Tenancy OCID',
    user_ocid: 'User OCID',
    fingerprint: 'Fingerprint',
    private_key: 'Private Key'
  };

  return (
    <div className="space-y-4">
      <p style={{ color: 'var(--text-tertiary)' }} className="text-sm">
        Enter your {CLOUD_PROVIDERS[provider].name} credentials for {authMethod === 'role_arn' ? 'Role ARN' : authMethod === 'access_keys' ? 'Access Keys' : authMethod === 'spn' ? 'Service Principal' : 'API'} authentication.
      </p>
      <div className="space-y-4">
        {fields.map((field) => (
          <div key={field}>
            <label style={{ color: 'var(--text-secondary)' }} className="block text-sm font-medium mb-2">
              {fieldLabels[field]}
            </label>
            <input
              type={field.includes('key') || field.includes('secret') || field.includes('private') ? 'password' : 'text'}
              value={credentials[field] || ''}
              onChange={(e) => onCredentialChange(field, e.target.value)}
              placeholder={`Enter ${fieldLabels[field].toLowerCase()}`}
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              className="w-full px-3 py-2 rounded-lg border placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors duration-200"
            />
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Step 3: Validation Result
 */
function Step3({ validationStatus, validationMessage, validationError, provider, credentials }) {
  return (
    <div className="space-y-6">
      {/* Status Indicator */}
      <div className="flex justify-center">
        {validationStatus === 'validating' && (
          <div className="flex flex-col items-center gap-4">
            <div style={{ borderColor: 'var(--border-primary)', borderTopColor: 'rgb(59, 130, 246)' }} className="w-16 h-16 rounded-full border-4 animate-spin transition-colors duration-200" />
            <p style={{ color: 'var(--text-secondary)' }} className="font-medium">{validationMessage}</p>
          </div>
        )}
        {validationStatus === 'success' && (
          <div className="flex flex-col items-center gap-4">
            <div className="w-16 h-16 rounded-full bg-green-500/20 flex items-center justify-center">
              <svg className="w-8 h-8 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            </div>
            <p className="text-green-400 font-semibold text-lg">{validationMessage}</p>
          </div>
        )}
        {validationStatus === 'failed' && (
          <div className="flex flex-col items-center gap-4">
            <div className="w-16 h-16 rounded-full bg-red-500/20 flex items-center justify-center">
              <svg className="w-8 h-8 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <p className="text-red-400 font-semibold text-lg">Validation Failed</p>
            <p style={{ color: 'var(--text-tertiary)' }} className="text-sm text-center">{validationError}</p>
          </div>
        )}
      </div>

      {/* Account Summary */}
      {validationStatus !== 'validating' && (
        <div style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }} className="rounded-lg p-4 border transition-colors duration-200">
          <h4 style={{ color: 'var(--text-secondary)' }} className="text-sm font-semibold mb-3">Account Summary</h4>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">Provider:</span>
              <span style={{ color: 'var(--text-primary)' }} className="text-sm font-medium">
                {CLOUD_PROVIDERS[provider].name}
              </span>
            </div>
            <div className="flex justify-between">
              <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">Status:</span>
              <span className={`text-sm font-medium ${
                validationStatus === 'success' ? 'text-green-400' : 'text-red-400'
              }`}>
                {validationStatus === 'success' ? 'Validated' : 'Failed Validation'}
              </span>
            </div>
            <div className="flex justify-between">
              <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">Timestamp:</span>
              <span style={{ color: 'var(--text-primary)' }} className="text-sm font-medium">
                {new Date().toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
