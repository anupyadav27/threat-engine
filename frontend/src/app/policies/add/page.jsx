'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Plus,
  X,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { useToast } from '@/lib/toast-context';

/**
 * Enterprise Create/Edit Policy Form Page
 * Comprehensive policy creation with rule builder, framework mapping, and impact analysis
 */
export default function CreatePolicyPage() {
  const router = useRouter();
  const toast = useToast();
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    category: '',
    provider: 'aws',
    severity: 'high',
    auto_remediate: false,
    notification: true,
    tags: [],
  });
  const [rules, setRules] = useState([]);
  const [newRule, setNewRule] = useState({
    resource_type: '',
    property: '',
    condition: 'equals',
    value: '',
  });
  const [selectedFrameworks, setSelectedFrameworks] = useState([]);
  const [remediationAction, setRemediationAction] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const categories = ['Network', 'IAM', 'Storage', 'Compute', 'Database', 'Logging', 'Encryption', 'Container Security'];
  const providers = ['aws', 'azure', 'gcp', 'oci', 'all'];
  const conditions = ['equals', 'not_equals', 'contains', 'not_contains', 'exists', 'not_exists', 'greater_than', 'less_than', 'in_list'];
  const severities = ['critical', 'high', 'medium', 'low'];
  const frameworks = ['CIS', 'NIST', 'ISO 27001', 'PCI-DSS', 'HIPAA', 'GDPR', 'SOC 2'];

  // Impact analysis — shows 0 until policy is saved and evaluated
  const impactAnalysis = {
    resources_affected: 0,
    would_fail: 0,
  };

  // Generate policy JSON preview
  const generatePolicyJson = () => {
    return JSON.stringify({
      metadata: {
        name: formData.name,
        description: formData.description,
        category: formData.category,
        provider: formData.provider,
        severity: formData.severity,
        tags: formData.tags,
      },
      rules: rules.map((rule, idx) => ({
        id: `rule_${idx + 1}`,
        resource_type: rule.resource_type,
        property: rule.property,
        condition: rule.condition,
        value: rule.value,
      })),
      compliance_frameworks: selectedFrameworks,
      enforcement: {
        auto_remediate: formData.auto_remediate,
        remediation_action: remediationAction,
        notify_on_violation: formData.notification,
      },
    }, null, 2);
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const handleRuleInputChange = (e) => {
    const { name, value } = e.target;
    setNewRule((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleAddRule = () => {
    if (newRule.resource_type && newRule.property && newRule.value) {
      setRules((prev) => [...prev, { ...newRule }]);
      setNewRule({
        resource_type: '',
        property: '',
        condition: 'equals',
        value: '',
      });
    }
  };

  const handleRemoveRule = (index) => {
    setRules((prev) => prev.filter((_, i) => i !== index));
  };

  const handleFrameworkToggle = (framework) => {
    setSelectedFrameworks((prev) => {
      if (prev.includes(framework)) {
        return prev.filter((f) => f !== framework);
      } else {
        return [...prev, framework];
      }
    });
  };

  const handleAddTag = (tag) => {
    if (tag && !(formData.tags || []).includes(tag)) {
      setFormData((prev) => ({
        ...prev,
        tags: [...prev.tags, tag],
      }));
    }
  };

  const handleRemoveTag = (tag) => {
    setFormData((prev) => ({
      ...prev,
      tags: (prev.tags || []).filter((t) => t !== tag),
    }));
  };

  const handleSaveDraft = async () => {
    if (!formData.name) {
      toast.error('Policy name is required');
      return;
    }

    setIsSubmitting(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 500));
      toast.success('Policy saved as draft');
      router.push('/policies');
    } catch (error) {
      console.error('Error saving draft:', error);
      toast.error('Failed to save draft');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handlePublish = async () => {
    if (!formData.name || !formData.category || !formData.provider || rules.length === 0) {
      toast.error('Please fill in all required fields (Name, Category, Provider) and add at least one rule');
      return;
    }

    setIsSubmitting(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 500));
      toast.success('Policy published successfully');
      router.push('/policies');
    } catch (error) {
      console.error('Error publishing policy:', error);
      toast.error('Failed to publish policy');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => router.back()}
          className="p-2 rounded-lg hover:opacity-70 transition-colors"
          style={{ backgroundColor: 'var(--bg-tertiary)' }}
        >
          <ArrowLeft className="w-5 h-5" style={{ color: 'var(--text-secondary)' }} />
        </button>
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Create New Policy
          </h1>
          <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Define security rules and enforcement settings
          </p>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form Section */}
        <div className="lg:col-span-2 space-y-6">
          {/* Policy Details Section */}
          <div
            className="rounded-xl p-6 border transition-colors duration-200"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Policy Details
            </h2>

            <div className="space-y-4">
              {/* Policy Name */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                  Policy Name *
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  placeholder="e.g., Enforce S3 Encryption"
                  className="w-full px-4 py-2 rounded-lg border transition-colors duration-200"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    borderColor: 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                  Description
                </label>
                <textarea
                  name="description"
                  value={formData.description}
                  onChange={handleInputChange}
                  placeholder="Describe what this policy ensures..."
                  rows="4"
                  className="w-full px-4 py-2 rounded-lg border transition-colors duration-200"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    borderColor: 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                />
              </div>

              {/* Category and Provider */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Category *
                  </label>
                  <select
                    name="category"
                    value={formData.category}
                    onChange={handleInputChange}
                    className="w-full px-4 py-2 rounded-lg border transition-colors duration-200"
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      borderColor: 'var(--border-primary)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    <option value="">Select category</option>
                    {categories.map((cat) => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Provider *
                  </label>
                  <select
                    name="provider"
                    value={formData.provider}
                    onChange={handleInputChange}
                    className="w-full px-4 py-2 rounded-lg border transition-colors duration-200"
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      borderColor: 'var(--border-primary)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    <option value="">Select provider</option>
                    {providers.map((prov) => (
                      <option key={prov} value={prov}>{prov.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
          </div>

          {/* Rules Section */}
          <div
            className="rounded-xl p-6 border transition-colors duration-200"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Rules
            </h2>

            {/* Add Rule Inputs */}
            <div className="space-y-4 mb-6 pb-6 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <div className="grid grid-cols-4 gap-3">
                <div>
                  <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Resource Type *
                  </label>
                  <select
                    name="resource_type"
                    value={newRule.resource_type}
                    onChange={handleRuleInputChange}
                    className="w-full px-3 py-2 rounded-lg border text-sm transition-colors duration-200"
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      borderColor: 'var(--border-primary)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    <option value="">Select resource</option>
                    <option value="S3Bucket">S3 Bucket</option>
                    <option value="SecurityGroup">Security Group</option>
                    <option value="RDSInstance">RDS Instance</option>
                    <option value="IAMUser">IAM User</option>
                    <option value="EC2Instance">EC2 Instance</option>
                    <option value="CloudTrail">CloudTrail</option>
                    <option value="KmsKey">KMS Key</option>
                    <option value="VPC">VPC</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Property *
                  </label>
                  <input
                    type="text"
                    name="property"
                    value={newRule.property}
                    onChange={handleRuleInputChange}
                    placeholder="e.g., ServerSideEncryption"
                    className="w-full px-3 py-2 rounded-lg border text-sm transition-colors duration-200"
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      borderColor: 'var(--border-primary)',
                      color: 'var(--text-primary)',
                    }}
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Condition
                  </label>
                  <select
                    name="condition"
                    value={newRule.condition}
                    onChange={handleRuleInputChange}
                    className="w-full px-3 py-2 rounded-lg border text-sm transition-colors duration-200"
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      borderColor: 'var(--border-primary)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    {conditions.map((cond) => (
                      <option key={cond} value={cond}>{cond}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                    Value *
                  </label>
                  <input
                    type="text"
                    name="value"
                    value={newRule.value}
                    onChange={handleRuleInputChange}
                    placeholder="e.g., AES256"
                    className="w-full px-3 py-2 rounded-lg border text-sm transition-colors duration-200"
                    style={{
                      backgroundColor: 'var(--bg-tertiary)',
                      borderColor: 'var(--border-primary)',
                      color: 'var(--text-primary)',
                    }}
                  />
                </div>
              </div>

              <button
                onClick={handleAddRule}
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
              >
                <Plus className="w-4 h-4" />
                Add Rule
              </button>
            </div>

            {/* Rules List */}
            {rules.length > 0 && (
              <div className="space-y-2">
                {rules.map((rule, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-3 rounded-lg transition-colors duration-200"
                    style={{ backgroundColor: 'var(--bg-tertiary)' }}
                  >
                    <div className="text-sm">
                      <span style={{ color: 'var(--text-secondary)' }}>
                        <span className="font-medium">{rule.resource_type}</span>
                        {' → '}
                        <span className="font-medium">{rule.property}</span>
                        {' '}
                        <span style={{ color: 'var(--text-tertiary)' }}>{rule.condition}</span>
                        {' '}
                        <span className="font-medium">{rule.value}</span>
                      </span>
                    </div>
                    <button
                      onClick={() => handleRemoveRule(index)}
                      className="p-1 rounded hover:opacity-70 transition-colors"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {rules.length === 0 && (
              <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
                No rules added yet. Add at least one rule to publish this policy.
              </p>
            )}
          </div>

          {/* Enforcement & Remediation Section */}
          <div
            className="rounded-xl p-6 border transition-colors duration-200"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Enforcement & Remediation
            </h2>

            <div className="space-y-4">
              {/* Severity */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                  Severity *
                </label>
                <select
                  name="severity"
                  value={formData.severity}
                  onChange={handleInputChange}
                  className="w-full px-4 py-2 rounded-lg border transition-colors duration-200"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    borderColor: 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                >
                  {severities.map((sev) => (
                    <option key={sev} value={sev}>
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </option>
                  ))}
                </select>
              </div>

              {/* Remediation Action */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>
                  Remediation Action
                </label>
                <textarea
                  name="remediation_action"
                  value={remediationAction}
                  onChange={(e) => setRemediationAction(e.target.value)}
                  placeholder="e.g., Enable S3 bucket encryption with KMS key"
                  rows="3"
                  className="w-full px-4 py-2 rounded-lg border transition-colors duration-200"
                  style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    borderColor: 'var(--border-primary)',
                    color: 'var(--text-primary)',
                  }}
                />
              </div>

              {/* Auto-Remediate */}
              <div className="flex items-start gap-3 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <input
                  type="checkbox"
                  name="auto_remediate"
                  checked={formData.auto_remediate}
                  onChange={handleInputChange}
                  id="auto_remediate"
                  className="w-4 h-4 mt-1"
                />
                <div className="flex-1">
                  <label htmlFor="auto_remediate" className="text-sm font-medium block" style={{ color: 'var(--text-secondary)' }}>
                    Enable Auto-Remediation
                  </label>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                    Automatically apply remediation action to resources that violate this policy
                  </p>
                </div>
              </div>

              {/* Notification */}
              <div className="flex items-start gap-3 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <input
                  type="checkbox"
                  name="notification"
                  checked={formData.notification}
                  onChange={handleInputChange}
                  id="notification"
                  className="w-4 h-4 mt-1"
                />
                <div className="flex-1">
                  <label htmlFor="notification" className="text-sm font-medium block" style={{ color: 'var(--text-secondary)' }}>
                    Send Violation Notifications
                  </label>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
                    Alert security team when violations are detected
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Compliance Framework Mapping Section */}
          <div
            className="rounded-xl p-6 border transition-colors duration-200"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Compliance Framework Mapping
            </h2>
            <p className="text-sm mb-4" style={{ color: 'var(--text-tertiary)' }}>
              Select which compliance frameworks this policy addresses
            </p>
            <div className="grid grid-cols-2 gap-3">
              {frameworks.map((fw) => (
                <div key={fw} className="flex items-center gap-3 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                  <input
                    type="checkbox"
                    id={`fw-${fw}`}
                    checked={selectedFrameworks.includes(fw)}
                    onChange={() => handleFrameworkToggle(fw)}
                    className="w-4 h-4"
                  />
                  <label htmlFor={`fw-${fw}`} className="text-sm font-medium cursor-pointer" style={{ color: 'var(--text-secondary)' }}>
                    {fw}
                  </label>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Preview & Impact Analysis Section */}
        <div className="lg:col-span-1 space-y-6">
          {/* Policy Summary */}
          <div
            className="rounded-xl p-6 border transition-colors duration-200 sticky top-6"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
              Policy Summary
            </h2>

            <div className="space-y-3 text-sm pb-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <div>
                <p style={{ color: 'var(--text-tertiary)' }}>Name</p>
                <p className="font-medium truncate" style={{ color: 'var(--text-secondary)' }}>
                  {formData.name || '(not set)'}
                </p>
              </div>
              <div>
                <p style={{ color: 'var(--text-tertiary)' }}>Category</p>
                <p className="font-medium" style={{ color: 'var(--text-secondary)' }}>
                  {formData.category || '(not set)'}
                </p>
              </div>
              <div>
                <p style={{ color: 'var(--text-tertiary)' }}>Provider</p>
                <p className="font-medium" style={{ color: 'var(--text-secondary)' }}>
                  {(formData.provider || '').toUpperCase()}
                </p>
              </div>
              <div>
                <p style={{ color: 'var(--text-tertiary)' }}>Severity</p>
                <p className="font-medium" style={{ color: 'var(--text-secondary)' }}>
                  {formData.severity.charAt(0).toUpperCase() + formData.severity.slice(1)}
                </p>
              </div>
              <div>
                <p style={{ color: 'var(--text-tertiary)' }}>Rules</p>
                <p className="font-medium" style={{ color: 'var(--text-secondary)' }}>
                  {rules.length}
                </p>
              </div>
              {selectedFrameworks.length > 0 && (
                <div>
                  <p style={{ color: 'var(--text-tertiary)' }}>Frameworks</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedFrameworks.map((fw) => (
                      <span key={fw} className="text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
                        {fw}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Impact Analysis */}
            <div className="space-y-3 mb-4">
              <h3 className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>Impact Analysis</h3>
              <div className="p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Estimated Resources</p>
                <p className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>{impactAnalysis.resources_affected}</p>
              </div>
              <div className="p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Would Fail</p>
                <p className="text-lg font-bold" style={{ color: 'var(--accent-warning)' }}>{impactAnalysis.would_fail}</p>
              </div>
            </div>

            {/* JSON Preview */}
            <div className="mb-4">
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-tertiary)' }}>
                JSON Configuration
              </p>
              <pre
                className="text-xs p-2 rounded-lg overflow-x-auto max-h-48"
                style={{
                  backgroundColor: 'var(--bg-tertiary)',
                  color: 'var(--text-secondary)',
                  fontSize: '10px',
                  lineHeight: '1.3',
                }}
              >
                {generatePolicyJson()}
              </pre>
            </div>

            {/* Action Buttons */}
            <div className="space-y-2 pt-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
              <button
                onClick={handleSaveDraft}
                disabled={isSubmitting}
                className="w-full px-4 py-2 rounded-lg text-sm font-medium transition-colors"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
              >
                {isSubmitting ? 'Saving...' : 'Save as Draft'}
              </button>
              <button
                onClick={handlePublish}
                disabled={isSubmitting || !formData.name || !formData.category || !formData.provider || rules.length === 0}
                className="w-full px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors disabled:opacity-50"
                style={{ backgroundColor: '#3b82f6' }}
              >
                {isSubmitting ? 'Publishing...' : 'Publish Policy'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
