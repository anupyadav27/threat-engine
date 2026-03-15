'use client';

import { useEffect, useState } from 'react';
import {
  BookOpen,
  Code2,
  AlertTriangle,
  CheckCircle,
  Copy,
  Download,
  Plus,
  Search,
  AlertCircle,
  RefreshCw,
  Eye,
  EyeOff,
  Zap,
  Filter,
} from 'lucide-react';
import { fetchView, postToEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import FilterBar from '@/components/shared/FilterBar';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';

/**
 * Rule Management Page
 * Browse, create, validate, and manage security compliance rules
 */
export default function RulesPage() {
  const [loading, setLoading] = useState(true);
  const [rules, setRules] = useState([]);
  const [ruleStats, setRuleStats] = useState({});
  const [templates, setTemplates] = useState([]);
  const [filteredRules, setFilteredRules] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [showEditor, setShowEditor] = useState(false);
  const [editorContent, setEditorContent] = useState('');
  const [validationResult, setValidationResult] = useState(null);
  const [showYamlEditor, setShowYamlEditor] = useState(false);

  const [activeFilters, setActiveFilters] = useState({
    provider: [],
    service: [],
    severity: [],
    framework: [],
    status: [],
  });

  // Fetch rules via BFF
  useEffect(() => {
    const fetchRules = async () => {
      setLoading(true);
      try {
        const data = await fetchView('rules');
        if (data.error) { console.warn('Error fetching rules:', data.error); return; }
        if (data.rules)      setRules(data.rules);
        if (data.kpi)         setRuleStats(data.kpi);
        else if (data.statistics) setRuleStats(data.statistics);
        if (data.templates)   setTemplates(data.templates);
      } catch (error) {
        console.warn('Error fetching rules:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchRules();
  }, []);

  // Apply filters and search
  useEffect(() => {
    let filtered = [...rules];

    if (searchTerm) {
      filtered = filtered.filter(
        (r) =>
          r.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          r.rule_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
          r.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if ((activeFilters.provider || []).length > 0) {
      filtered = filtered.filter((r) => (activeFilters.provider || []).includes(r.provider));
    }
    if ((activeFilters.service || []).length > 0) {
      filtered = filtered.filter((r) => (activeFilters.service || []).includes(r.service));
    }
    if ((activeFilters.severity || []).length > 0) {
      filtered = filtered.filter((r) => (activeFilters.severity || []).includes(r.severity));
    }
    if ((activeFilters.framework || []).length > 0) {
      filtered = filtered.filter((r) => r.frameworks.some((f) => (activeFilters.framework || []).includes(f)));
    }
    if ((activeFilters.status || []).length > 0) {
      filtered = filtered.filter((r) => (activeFilters.status || []).includes(r.status));
    }

    setFilteredRules(filtered);
  }, [rules, activeFilters, searchTerm]);

  const uniqueProviders = [...new Set(rules.map((r) => r.provider))].sort();
  const uniqueServices = [...new Set(rules.map((r) => r.service))].sort();
  const uniqueFrameworks = [...new Set(rules.flatMap((r) => r.frameworks))].sort();

  const columns = [
    {
      accessorKey: 'name',
      header: 'Rule Name',
      cell: (info) => (
        <div>
          <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            {info.getValue()}
          </p>
          <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
            {info.row.original.rule_id}
          </p>
        </div>
      ),
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'service',
      header: 'Service',
      cell: (info) => (
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'frameworks',
      header: 'Frameworks',
      cell: (info) => (
        <div className="flex flex-wrap gap-1">
          {info.getValue().slice(0, 2).map((f) => (
            <span key={f} className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--accent-primary)' }}>
              {f}
            </span>
          ))}
          {info.getValue().length > 2 && (
            <span className="text-xs px-2 py-1" style={{ color: 'var(--text-tertiary)' }}>
              +{info.getValue().length - 2}
            </span>
          )}
        </div>
      ),
    },
    {
      accessorKey: 'rule_type',
      header: 'Type',
      cell: (info) => (
        <span
          className="text-xs px-2 py-1 rounded font-semibold"
          style={{
            backgroundColor: info.getValue() === 'custom' ? 'rgba(168, 85, 247, 0.1)' : 'rgba(59, 130, 246, 0.1)',
            color: info.getValue() === 'custom' ? 'var(--accent-primary)' : 'var(--accent-primary)',
          }}
        >
          {info.getValue() === 'custom' ? 'Custom' : 'Built-in'}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => (
        <div className="flex items-center gap-1">
          {info.getValue() === 'active' ? (
            <CheckCircle className="w-4 h-4" style={{ color: 'var(--accent-success)' }} />
          ) : (
            <AlertCircle className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          )}
          <span className="text-xs" style={{ color: info.getValue() === 'active' ? 'var(--accent-success)' : 'var(--text-muted)' }}>
            {info.getValue() === 'active' ? 'Active' : 'Inactive'}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'passing_resources',
      header: 'Compliance',
      cell: (info) => {
        const total = info.row.original.tested_resources;
        const passing = info.getValue();
        const percentage = total > 0 ? ((passing / total) * 100).toFixed(1) : 0;
        return (
          <span className="text-xs font-semibold" style={{ color: percentage >= 80 ? 'var(--accent-success)' : 'var(--accent-danger)' }}>
            {passing}/{total} ({percentage}%)
          </span>
        );
      },
    },
  ];

  const filterOptions = [
    { name: 'provider', label: 'Provider', options: uniqueProviders },
    { name: 'service', label: 'Service', options: uniqueServices },
    { name: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
    { name: 'framework', label: 'Framework', options: uniqueFrameworks },
    { name: 'status', label: 'Status', options: ['active', 'inactive'] },
  ];

  const handleFilterChange = (filterName, value) => {
    setActiveFilters((prev) => {
      const newFilters = { ...prev };
      if (newFilters[filterName].includes(value)) {
        newFilters[filterName] = newFilters[filterName].filter((v) => v !== value);
      } else {
        newFilters[filterName] = [...newFilters[filterName], value];
      }
      return newFilters;
    });
  };

  const handleValidateRule = async () => {
    try {
      const ruleData = { yaml: editorContent };
      const res = await postToEngine('rule', '/api/v1/rules/validate', ruleData);
      setValidationResult(res);
    } catch (error) {
      setValidationResult({ error: true, message: error.message });
    }
  };

  const handleGenerateFromTemplate = async () => {
    if (!selectedTemplate) return;
    try {
      const templateData = { template_id: selectedTemplate.id };
      const res = await postToEngine('rule', '/api/v1/rules/generate', templateData);
      if (res && res.yaml) {
        setEditorContent(res.yaml);
      }
    } catch (error) {
      console.warn('Error generating from template:', error);
    }
  };

  const handleExportRules = () => {
    const csv = [
      ['Rule ID', 'Name', 'Provider', 'Service', 'Severity', 'Status', 'Type', 'Frameworks', 'Passing', 'Total'],
      ...filteredRules.map((r) => [
        r.rule_id,
        r.name,
        r.provider,
        r.service,
        r.severity,
        r.status,
        r.rule_type,
        r.frameworks.join('; '),
        r.passing_resources,
        r.tested_resources,
      ]),
    ]
      .map((row) => row.map((cell) => `"${cell}"`).join(','))
      .join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rules-${new Date().toISOString()}.csv`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Rule Management & Control
        </h1>
        <p className="mt-1" style={{ color: 'var(--text-secondary)' }}>
          Create, validate, and manage compliance rules across cloud environments
        </p>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
        <KpiCard
          title="Total Rules"
          value={ruleStats.totalRules || ruleStats.total_rules || 0}
          subtitle="Deployed"
          icon={<BookOpen className="w-5 h-5" />}
          color="blue"
        />
        <KpiCard
          title="Active Rules"
          value={ruleStats.activeRules || ruleStats.active_rules || 0}
          subtitle="Enabled"
          icon={<CheckCircle className="w-5 h-5" />}
          color="green"
        />
        <KpiCard
          title="Built-in Rules"
          value={ruleStats.builtInRules || ruleStats.built_in_rules || 0}
          subtitle="Provided"
          icon={<Code2 className="w-5 h-5" />}
          color="cyan"
        />
        <KpiCard
          title="Custom Rules"
          value={ruleStats.customRules || ruleStats.custom_rules || 0}
          subtitle="Custom"
          icon={<Zap className="w-5 h-5" />}
          color="purple"
        />
        <KpiCard
          title="Providers"
          value={Object.keys(ruleStats.byProvider || {}).length || ruleStats.providers || 0}
          subtitle="Covered"
          icon={<Filter className="w-5 h-5" />}
          color="orange"
        />
        <KpiCard
          title="Frameworks"
          value={uniqueFrameworks.length}
          subtitle="Mapped"
          icon={<Filter className="w-5 h-5" />}
          color="red"
        />
      </div>

      {/* Rule Templates Section */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
          Rule Templates
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          {templates.map((template) => (
            <div
              key={template.id}
              onClick={() => setSelectedTemplate(template)}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${selectedTemplate?.id === template.id ? 'ring-2' : ''}`}
              style={{
                backgroundColor: selectedTemplate?.id === template.id ? 'var(--bg-secondary)' : 'transparent',
                borderColor: selectedTemplate?.id === template.id ? 'var(--accent-primary)' : 'var(--border-primary)',
                ringColor: 'var(--accent-primary)',
              }}
            >
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h3 className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
                    {template.name}
                  </h3>
                  <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                    {template.description}
                  </p>
                </div>
                {selectedTemplate?.id === template.id && (
                  <CheckCircle className="w-5 h-5" style={{ color: 'var(--accent-primary)' }} />
                )}
              </div>
              <div className="flex gap-2 mt-3">
                <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--accent-primary)' }}>
                  {template.framework}
                </span>
                <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                  {template.provider}
                </span>
              </div>
            </div>
          ))}
        </div>
        {selectedTemplate && (
          <button
            onClick={handleGenerateFromTemplate}
            className="w-full px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors"
            style={{ backgroundColor: 'var(--accent-primary)' }}
          >
            <Plus className="w-4 h-4 inline mr-2" />
            Generate from Template
          </button>
        )}
      </div>

      {/* YAML Rule Editor */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Rule Editor & Validator
          </h2>
          <button
            onClick={() => setShowYamlEditor(!showYamlEditor)}
            className="inline-flex items-center gap-2 px-3 py-1 rounded text-sm"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}
          >
            {showYamlEditor ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {showYamlEditor ? 'Hide' : 'Show'} Editor
          </button>
        </div>

        {showYamlEditor && (
          <div className="space-y-4">
            <div>
              <label className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                Rule YAML Definition
              </label>
              <textarea
                value={editorContent}
                onChange={(e) => setEditorContent(e.target.value)}
                placeholder={`name: Example Rule
provider: AWS
service: S3
severity: critical
description: Check for S3 bucket encryption
metadata:
  framework: CIS
  control_id: CIS-2.3.1`}
                className="w-full mt-2 p-4 rounded-lg font-mono text-sm border"
                rows={12}
                style={{
                  backgroundColor: 'var(--bg-secondary)',
                  borderColor: 'var(--border-primary)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>

            <div className="flex gap-2">
              <button
                onClick={handleValidateRule}
                className="px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors flex items-center gap-2"
                style={{ backgroundColor: 'var(--accent-primary)' }}
              >
                <RefreshCw className="w-4 h-4" />
                Validate Rule
              </button>
              <button
                onClick={() => {
                  const blob = new Blob([editorContent], { type: 'text/plain' });
                  const url = window.URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = 'rule.yaml';
                  a.click();
                }}
                className="px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}
              >
                <Download className="w-4 h-4" />
                Export YAML
              </button>
            </div>

            {validationResult && (
              <div
                className="p-4 rounded-lg border"
                style={{
                  backgroundColor: validationResult.error ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                  borderColor: validationResult.error ? 'var(--accent-danger)' : 'var(--accent-success)',
                }}
              >
                <div className="flex gap-2">
                  {validationResult.error ? (
                    <AlertCircle className="w-5 h-5" style={{ color: 'var(--accent-danger)' }} />
                  ) : (
                    <CheckCircle className="w-5 h-5" style={{ color: 'var(--accent-success)' }} />
                  )}
                  <div>
                    <p className="font-semibold text-sm" style={{ color: validationResult.error ? 'var(--accent-danger)' : 'var(--accent-success)' }}>
                      {validationResult.error ? 'Validation Failed' : 'Validation Passed'}
                    </p>
                    <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                      {validationResult.message}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Rules Table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-3 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search rules by name, ID, or description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 rounded-lg border"
              style={{
                backgroundColor: 'var(--bg-secondary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-primary)',
              }}
            />
          </div>
          <button
            onClick={handleExportRules}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors"
            style={{ backgroundColor: 'var(--accent-primary)' }}
          >
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>

        <div>
          <h2 className="text-lg font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
            Rules Library
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {filteredRules.length} of {rules.length} rules
          </p>
        </div>

        <FilterBar filters={filterOptions} activeFilters={activeFilters} onFilterChange={handleFilterChange} />

        <DataTable
          data={filteredRules}
          columns={columns}
          pageSize={12}
          loading={loading}
          emptyMessage="No rules found matching your filters"
        />
      </div>

      {/* Compliance Guidelines */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-start gap-4">
          <AlertTriangle className="w-6 h-6 flex-shrink-0" style={{ color: 'var(--accent-warning)' }} />
          <div>
            <h3 className="font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
              Rule Development Best Practices
            </h3>
            <ul className="space-y-2 text-sm" style={{ color: 'var(--text-secondary)' }}>
              <li>Define clear rule names and descriptions for auditors</li>
              <li>Map rules to specific controls in compliance frameworks</li>
              <li>Test rules against known compliant and non-compliant resources</li>
              <li>Version control all custom rules in Git repositories</li>
              <li>Review and update rules quarterly for new AWS/Azure/GCP features</li>
              <li>Document rule logic and rationale for future maintainers</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
