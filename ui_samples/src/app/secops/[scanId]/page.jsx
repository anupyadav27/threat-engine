'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';
import {
  ChevronLeft, Code2, GitBranch, Copy, Check,
  ChevronDown, ChevronRight, ShieldAlert, FileCode,
  Languages, AlertTriangle, Info, X, Lightbulb,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import FilterBar from '@/components/shared/FilterBar';
import SeverityDonut from '@/components/charts/SeverityDonut';

// ---------------------------------------------------------------------------
// Constants & helpers
// ---------------------------------------------------------------------------
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function normalizeSev(s) {
  if (!s) return 'info';
  const v = String(s).toLowerCase();
  if (v === 'blocker') return 'critical';
  if (v === 'major')   return 'high';
  if (v === 'minor')   return 'medium';
  return v;
}

function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    hour12: true,
  });
}

// Security rule patterns — rule_id must contain one of these to be classified as a security finding
const SECURITY_RULE_PATTERNS = [
  'securitysensitive', 'security_sensitive',
  'injection', 'xss', 'sqli', 'sql_injection', 'formatting_sql',
  'path_traversal', 'command_injection',
  'pickle', 'deserialization', 'deserializ',
  'ssrf', 'unvalidated_url', 'unrestricted_outbound',
  'debug_mode', 'hardcoded', 'credentials_should_not',
  'weak_hashing', 'pseudorandom', 'prng',
  'open_redirect', 'render_template_string',
  'bucket_ownership', 's3_operations_should_verify',
  'configuring_loggers', 'dynamically_executing',
  'insecure_deserialization', 'insecure_random',
  'allowing_unrestricted',
];

// Code quality rule patterns — if rule_id contains these, it is definitively NOT a security finding
const QUALITY_RULE_PATTERNS = [
  'docstring', 'einops', 'reachable', 'cognitive_complexity',
  'shadowed_by_local', 'builtins_should_not_be_shadowed',
  'dtype_parameter', 'pandas', 'pattern_should_be_valid',
  'except_blocks_should_be_able',
];

function isSecurityFinding(f) {
  const ruleId = (f.rule_id || '').toLowerCase();
  const msg    = (f.message || '').toLowerCase();
  const cat    = (f.metadata?.category || '').toLowerCase();

  // First: definitively exclude known code quality patterns
  if (QUALITY_RULE_PATTERNS.some(p => ruleId.includes(p))) return false;

  // Category explicitly tagged as security by the scanner
  if (cat === 'security' || cat.includes('vulnerability') || cat.includes('owasp')) return true;

  // Rule ID matches a known security pattern — primary signal
  if (SECURITY_RULE_PATTERNS.some(p => ruleId.includes(p))) return true;

  // Message contains a clear security signal
  const MSG_SIGNALS = ['xss', 'sql injection', 'hardcoded', 'path traversal', 'command injection',
    'ssrf', 'deserialization', 'open redirect', 'weak hash', 'security-sensitive'];
  if (MSG_SIGNALS.some(p => msg.includes(p))) return true;

  return false;
}

// ---------------------------------------------------------------------------
// Fix hints: before/after code examples per rule pattern
// ---------------------------------------------------------------------------
const FIX_HINTS = {
  sql_injection: {
    title: 'Use parameterized queries — never interpolate user input into SQL',
    before: `# VULNERABLE\ncursor.execute(f"SELECT * FROM users WHERE id={user_id}")`,
    after:  `# FIXED\ncursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))`,
  },
  xss_html: {
    title: 'Escape output before inserting into HTML — never concatenate raw user data',
    before: `# VULNERABLE\nreturn "<h1>" + username + "</h1>"`,
    after:  `# FIXED\nfrom markupsafe import escape\nreturn "<h1>" + escape(username) + "</h1>"`,
  },
  open_redirect: {
    title: 'Validate redirect target — only allow relative paths or trusted domains',
    before: `# VULNERABLE\nreturn redirect(request.args.get("next"))`,
    after:  `# FIXED\nnext_url = request.args.get("next", "/")\nif not next_url.startswith("/"):\n    abort(400)\nreturn redirect(next_url)`,
  },
  path_traversal: {
    title: 'Resolve and validate paths against a known safe base directory',
    before: `# VULNERABLE\nwith open(BASE_DIR + filename) as f: ...`,
    after:  `# FIXED\nimport os\nsafe = os.path.realpath(os.path.join(BASE_DIR, filename))\nif not safe.startswith(BASE_DIR):\n    abort(400)\nwith open(safe) as f: ...`,
  },
  command_injection: {
    title: 'Pass arguments as a list — never build shell strings from user input',
    before: `# VULNERABLE\nos.system("ping " + host)`,
    after:  `# FIXED\nimport subprocess\nsubprocess.run(["ping", "-c", "1", host], check=True)`,
  },
  hardcoded_secret: {
    title: 'Read secrets from environment variables or a secrets manager — never hardcode',
    before: `# VULNERABLE\nAPI_KEY = "abc123secret"`,
    after:  `# FIXED\nimport os\nAPI_KEY = os.environ["API_KEY"]  # or use AWS Secrets Manager`,
  },
  insecure_hash: {
    title: 'Use a modern hash (SHA-256+) and always salt password hashes',
    before: `# VULNERABLE\nhashlib.md5(password.encode()).hexdigest()`,
    after:  `# FIXED — for passwords use bcrypt/argon2, not raw SHA\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())`,
  },
  insecure_random: {
    title: 'Use the cryptographically secure secrets module for tokens and secrets',
    before: `# VULNERABLE\ntoken = str(random.randint(0, 999999))`,
    after:  `# FIXED\nimport secrets\ntoken = secrets.token_hex(32)`,
  },
  pickle: {
    title: 'Never deserialize untrusted data with pickle — use JSON or a safe format',
    before: `# VULNERABLE\nobj = pickle.loads(user_data)`,
    after:  `# FIXED\nimport json\nobj = json.loads(user_data)  # validate schema after loading`,
  },
  ssrf: {
    title: 'Validate URLs against an allowlist before making outbound requests',
    before: `# VULNERABLE\nrequests.get(user_supplied_url)`,
    after:  `# FIXED\nfrom urllib.parse import urlparse\nparsed = urlparse(user_supplied_url)\nif parsed.hostname not in ALLOWED_HOSTS:\n    abort(400)\nrequests.get(user_supplied_url)`,
  },
  debug_mode: {
    title: 'Disable debug mode in production — use environment variables',
    before: `# VULNERABLE\napp.run(debug=True)`,
    after:  `# FIXED\nimport os\napp.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")`,
  },
  logger_config: {
    title: 'Avoid logging sensitive data — configure log level via environment',
    before: `# RISKY\nlogging.basicConfig(level=logging.DEBUG)\nlogger.debug("User data: %s", user_input)`,
    after:  `# FIXED\nLOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")\nlogging.basicConfig(level=getattr(logging, LOG_LEVEL))\n# Never log raw user input or credentials`,
  },
  dynamic_exec: {
    title: 'Never execute dynamically constructed code — use safe alternatives',
    before: `# VULNERABLE\nexec(user_code)\neval(user_expression)`,
    after:  `# FIXED — use a safe parser or restricted interpreter\nimport ast\ntree = ast.parse(expr, mode='eval')\n# Validate nodes before eval or use a sandboxed approach`,
  },
  s3_bucket_owner: {
    title: 'Always verify S3 bucket ownership using ExpectedBucketOwner',
    before: `# VULNERABLE — could hit a bucket in another AWS account\ns3.get_object(Bucket=bucket_name, Key=key)`,
    after:  `# FIXED — prevents bucket takeover via confused deputy\ns3.get_object(\n    Bucket=bucket_name, Key=key,\n    ExpectedBucketOwner=ACCOUNT_ID,\n)`,
  },
  outbound_allowlist: {
    title: 'Restrict outbound connections to an explicit allowlist',
    before: `# VULNERABLE — any URL can be fetched\nrequests.get(target_url)`,
    after:  `# FIXED — validate against allowlist before connecting\nALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}\nfrom urllib.parse import urlparse\nif urlparse(target_url).hostname not in ALLOWED_HOSTS:\n    raise ValueError("Blocked outbound request")\nrequests.get(target_url, timeout=5)`,
  },
  // Code quality hints shown in the Code Quality tab
  docstring: {
    title: 'Add a docstring describing purpose, args, and return value',
    before: `def process_data(records, threshold):\n    return [r for r in records if r.score > threshold]`,
    after:  `def process_data(records, threshold):\n    """Filter records above a score threshold.\n\n    Args:\n        records: List of record objects with a .score attribute.\n        threshold: Minimum score to include (exclusive).\n\n    Returns:\n        Filtered list of records.\n    """\n    return [r for r in records if r.score > threshold]`,
  },
  unreachable_code: {
    title: 'Remove dead code — statements after return/raise are never executed',
    before: `def get_value():\n    return result\n    print("done")  # never runs`,
    after:  `def get_value():\n    return result`,
  },
  shadowed_builtin: {
    title: 'Rename variable — do not shadow Python built-in names',
    before: `open = open("file.txt")   # shadows built-in open()\nlist = [1, 2, 3]           # shadows built-in list()`,
    after:  `file_handle = open("file.txt")  # safe name\nitems = [1, 2, 3]               # safe name`,
  },
};

function getFixHint(ruleId) {
  const r = (ruleId || '').toLowerCase();
  // Security fixes
  if (r.includes('sql') || r.includes('formatting_sql'))    return FIX_HINTS.sql_injection;
  if (r.includes('xss') || r.includes('html_concat') || r.includes('render_template_string')) return FIX_HINTS.xss_html;
  if (r.includes('redirect'))                               return FIX_HINTS.open_redirect;
  if (r.includes('path_traversal') || r.includes('traversal')) return FIX_HINTS.path_traversal;
  if (r.includes('command_injection') || r.includes('cmd') || r.includes('subprocess_shell')) return FIX_HINTS.command_injection;
  if (r.includes('credential') || r.includes('hardcoded') || r.includes('secret')) return FIX_HINTS.hardcoded_secret;
  if (r.includes('weak_hash') || r.includes('hashing_algorithm') || r.includes('md5') || r.includes('sha1')) return FIX_HINTS.insecure_hash;
  if (r.includes('pseudorandom') || r.includes('prng') || r.includes('random')) return FIX_HINTS.insecure_random;
  if (r.includes('pickle') || r.includes('deserialization'))return FIX_HINTS.pickle;
  if (r.includes('ssrf') || r.includes('unvalidated_url'))  return FIX_HINTS.ssrf;
  if (r.includes('debug_mode') || r.includes('debug'))      return FIX_HINTS.debug_mode;
  if (r.includes('configuring_logger') || r.includes('logger')) return FIX_HINTS.logger_config;
  if (r.includes('dynamically_executing') || r.includes('exec') || r.includes('eval')) return FIX_HINTS.dynamic_exec;
  if (r.includes('bucket_ownership') || r.includes('s3_operations')) return FIX_HINTS.s3_bucket_owner;
  if (r.includes('unrestricted_outbound') || r.includes('unrestricted_communication')) return FIX_HINTS.outbound_allowlist;
  // Code quality fixes
  if (r.includes('docstring'))                              return FIX_HINTS.docstring;
  if (r.includes('reachable'))                              return FIX_HINTS.unreachable_code;
  if (r.includes('shadowed') || r.includes('builtins_should_not')) return FIX_HINTS.shadowed_builtin;
  return null;
}

// ---------------------------------------------------------------------------
// FixModal — popup shown when user clicks "Help to Fix"
// ---------------------------------------------------------------------------
function FixModal({ finding, onClose }) {
  const raw      = finding._raw || finding;
  const fixHint  = getFixHint(raw.rule_id);
  const meta     = raw.metadata || {};

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50" onClick={onClose} />
      {/* Modal */}
      <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-2xl max-h-[85vh] overflow-y-auto rounded-2xl border shadow-2xl z-50"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

        {/* Header */}
        <div className="flex items-start justify-between px-5 py-4 border-b sticky top-0"
          style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-green-500/15 flex items-center justify-center flex-shrink-0">
              <Lightbulb className="w-4 h-4 text-green-400" />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                How to Fix
              </div>
              <div className="text-xs truncate max-w-[420px]" title={raw.rule_id} style={{ color: 'var(--text-tertiary)' }}>
                {raw.rule_id?.replace(/_/g, ' ')}
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors flex-shrink-0">
            <X className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* Vulnerability description */}
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-tertiary)' }}>
              What was detected
            </div>
            <div className="text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
              {raw.message || '—'}
            </div>
            <div className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>
              {raw.file_path}{raw.line_number ? `:${raw.line_number}` : ''}
            </div>
          </div>

          {/* Tags row */}
          {(meta.cwe || meta.owasp || meta.category) && (
            <div className="flex flex-wrap gap-2">
              {meta.cwe && (
                <span className="text-xs font-mono px-2 py-1 rounded-md bg-orange-500/10 text-orange-400 border border-orange-500/20">
                  {meta.cwe}
                </span>
              )}
              {meta.owasp && (
                <span className="text-xs px-2 py-1 rounded-md bg-red-500/10 text-red-400 border border-red-500/20">
                  {meta.owasp}
                </span>
              )}
              {meta.category && (
                <span className="text-xs px-2 py-1 rounded-md" style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-tertiary)' }}>
                  {meta.category}
                </span>
              )}
            </div>
          )}

          {/* Fix guidance */}
          {fixHint ? (
            <div className="space-y-3">
              <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>
                How to fix
              </div>
              <div className="text-sm text-green-300 font-medium">{fixHint.title}</div>
              <div className="rounded-xl overflow-hidden border border-green-500/20">
                <div className="grid grid-cols-2 divide-x divide-green-500/20">
                  <div className="p-4" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <div className="text-[10px] font-semibold uppercase tracking-wider mb-2.5 text-red-400">
                      Vulnerable code
                    </div>
                    <pre className="text-xs font-mono text-red-300/90 whitespace-pre-wrap leading-relaxed">{fixHint.before}</pre>
                  </div>
                  <div className="p-4" style={{ backgroundColor: 'var(--bg-card)' }}>
                    <div className="text-[10px] font-semibold uppercase tracking-wider mb-2.5 text-green-400">
                      Fixed code
                    </div>
                    <pre className="text-xs font-mono text-green-300/90 whitespace-pre-wrap leading-relaxed">{fixHint.after}</pre>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border p-4 text-center"
              style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              <div className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Review the rule documentation for remediation guidance
              </div>
              <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
                Search for <code className="font-mono">{raw.rule_id}</code> in your scanner's documentation
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Expanded row — compact summary + Help to Fix button
// ---------------------------------------------------------------------------
function ExpandedFindingRow({ finding, onOpenFix }) {
  const raw  = finding._raw || finding;
  const meta = raw.metadata || {};
  const fixHint = getFixHint(raw.rule_id);

  return (
    <div className="px-5 py-3 flex items-start gap-4 border-t"
      style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
      {/* Message */}
      <div className="flex-1 min-w-0">
        <div className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
          Message
        </div>
        <div className="text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
          {raw.message || '—'}
        </div>
        {/* Tags inline */}
        {(meta.cwe || meta.owasp) && (
          <div className="flex flex-wrap gap-1.5 mt-2">
            {meta.cwe && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">
                {meta.cwe}
              </span>
            )}
            {meta.owasp && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                {meta.owasp}
              </span>
            )}
          </div>
        )}
      </div>
      {/* Help to Fix button */}
      {fixHint && (
        <button
          onClick={() => onOpenFix && onOpenFix(finding)}
          className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-green-500/30 bg-green-500/10 text-green-400 text-xs font-semibold hover:bg-green-500/20 transition-colors">
          <Lightbulb className="w-3.5 h-3.5" />
          Help to Fix
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function SastScanDetailPage() {
  const params       = useParams();
  const router       = useRouter();
  const searchParams = useSearchParams();
  const scanId       = params.scanId;

  // ?rule= deep-link from Fix This First, ?tab= to open quality tab directly
  const ruleFilter   = searchParams.get('rule') || '';
  const tabParam     = searchParams.get('tab')  || '';

  const [scan,     setScan]     = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [activeTab, setActiveTab] = useState(tabParam === 'quality' ? 'quality' : 'security');
  const [copied,   setCopied]   = useState(false);
  const [secFilters, setSecFilters] = useState({ severity: '', language: '' });
  const [cqFilters,  setCqFilters]  = useState({ severity: '', language: '' });
  const [fixModalFinding, setFixModalFinding] = useState(null);  // finding shown in How-to-Fix modal

  // ---------------------------------------------------------------------------
  // Fetch data
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!scanId) return;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [scanData, findingsData] = await Promise.all([
          getFromEngine('secops', `/api/v1/secops/sast/scan/${scanId}/status?tenant_id=test-tenant`),
          getFromEngine('secops', `/api/v1/secops/sast/scan/${scanId}/findings?limit=500`),
        ]);
        if (scanData && !scanData.error) setScan(scanData);
        else setError(scanData?.error || scanData?.detail || 'Failed to load scan');

        const rawFindings = Array.isArray(findingsData)
          ? findingsData
          : (findingsData?.findings || []);
        setFindings(rawFindings);
      } catch (err) {
        setError(err?.message || 'Failed to load scan data');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [scanId]);

  // ---------------------------------------------------------------------------
  // Derived data
  // ---------------------------------------------------------------------------
  const normalizedFindings = useMemo(() => {
    return findings.map(f => ({
      ...f,
      _normalSev: normalizeSev(f.severity),
      _isSecurity: isSecurityFinding(f),
    })).sort((a, b) => (SEV_ORDER[a._normalSev] ?? 9) - (SEV_ORDER[b._normalSev] ?? 9));
  }, [findings]);

  const securityFindings = useMemo(() => normalizedFindings.filter(f => f._isSecurity), [normalizedFindings]);
  const codeQualityFindings = useMemo(() => normalizedFindings.filter(f => !f._isSecurity), [normalizedFindings]);

  // Languages list
  const allLanguages = useMemo(() => {
    const langs = new Set(normalizedFindings.map(f => f.language).filter(Boolean));
    return [...langs].sort();
  }, [normalizedFindings]);

  // Top rules (security findings)
  const topRules = useMemo(() => {
    const counts = {};
    securityFindings.forEach(f => {
      const r = f.rule_id || 'unknown';
      counts[r] = (counts[r] || 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [securityFindings]);

  // Donut data (security findings only)
  const donutData = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0 };
    securityFindings.forEach(f => {
      if (counts[f._normalSev] !== undefined) counts[f._normalSev]++;
    });
    return [
      { name: 'Critical', value: counts.critical, color: '#ef4444' },
      { name: 'High',     value: counts.high,     color: '#f97316' },
      { name: 'Medium',   value: counts.medium,   color: '#eab308' },
    ].filter(d => d.value > 0);
  }, [securityFindings]);

  // Filtered findings per tab
  const filteredSecurity = useMemo(() => {
    return securityFindings.filter(f => {
      if (ruleFilter && f.rule_id !== ruleFilter) return false;
      if (secFilters.severity && f._normalSev !== secFilters.severity) return false;
      if (secFilters.language && f.language   !== secFilters.language)  return false;
      return true;
    });
  }, [securityFindings, secFilters, ruleFilter]);

  const filteredCQ = useMemo(() => {
    return codeQualityFindings.filter(f => {
      if (cqFilters.severity && f._normalSev !== cqFilters.severity) return false;
      if (cqFilters.language && f.language   !== cqFilters.language)  return false;
      return true;
    });
  }, [codeQualityFindings, cqFilters]);

  // ---------------------------------------------------------------------------
  // Copy scan ID
  // ---------------------------------------------------------------------------
  const handleCopyId = useCallback(() => {
    navigator.clipboard.writeText(scanId).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [scanId]);

  // ---------------------------------------------------------------------------
  // Column definitions
  // ---------------------------------------------------------------------------
  const findingColumns = useMemo(() => [
    {
      accessorKey: '_normalSev',
      header: 'Severity',
      size: 100,
      cell: info => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'rule_id',
      header: 'Rule',
      size: 180,
      cell: info => {
        const v = info.getValue() || '—';
        return (
          <span className="text-sm font-semibold truncate block max-w-[160px]" title={v} style={{ color: 'var(--text-primary)' }}>
            {v}
          </span>
        );
      },
    },
    {
      id: 'file',
      header: 'File',
      cell: info => {
        const row = info.row.original;
        const file = row.file_path || '—';
        const line = row.line_number;
        const txt  = `${file}${line ? `:${line}` : ''}`;
        return (
          <span className="text-xs font-mono truncate block max-w-[180px]" title={txt} style={{ color: 'var(--text-secondary)' }}>
            {txt}
          </span>
        );
      },
    },
    {
      accessorKey: 'message',
      header: 'Message',
      cell: info => {
        const v = info.getValue() || '—';
        return (
          <span className="text-xs truncate block max-w-[240px]" title={v} style={{ color: 'var(--text-secondary)' }}>
            {v}
          </span>
        );
      },
    },
    {
      accessorKey: 'language',
      header: 'Language',
      size: 100,
      cell: info => {
        const v = info.getValue();
        if (!v) return <span style={{ color: 'var(--text-tertiary)' }}>—</span>;
        return (
          <span className="text-xs px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20">
            {v}
          </span>
        );
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 90,
      cell: info => {
        const v = info.getValue() || 'open';
        const cfg = {
          open:      'bg-orange-500/15 text-orange-400',
          resolved:  'bg-green-500/15 text-green-400',
          violation: 'bg-red-500/15 text-red-400',
        };
        return (
          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${cfg[v] || 'bg-slate-500/15 text-slate-400'}`}>
            {v}
          </span>
        );
      },
    },
  ], []);

  // Filter bar configs
  const filterDefs = [
    { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low', 'info'] },
    { key: 'language', label: 'Language', options: allLanguages },
  ];

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]" style={{ color: 'var(--text-tertiary)' }}>
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          Loading scan data...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-6 py-8 space-y-4">
        <button onClick={() => router.push('/secops')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Code Security
        </button>
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-red-400">Failed to load scan</div>
            <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{error}</div>
          </div>
        </div>
      </div>
    );
  }

  const repoName = scan?.project_name || scan?.repo_url?.split('/').pop() || scanId;
  const branch   = scan?.branch || 'main';
  const langs    = scan?.languages_detected || [];

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="px-6 pt-6 pb-0">

        {/* Back button */}
        <button onClick={() => router.push('/secops')}
          className="flex items-center gap-2 text-sm hover:opacity-75 transition-opacity mb-4"
          style={{ color: 'var(--text-secondary)' }}>
          <ChevronLeft className="w-4 h-4" />
          Code Security
        </button>

        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>{repoName}</h1>
              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border bg-blue-500/10 text-blue-400 border-blue-500/30">
                <GitBranch className="w-3 h-3" />
                {branch}
              </span>
              {scan?.status && <StatusIndicator status={scan.status} />}
            </div>
            <div className="flex items-center gap-2 mt-2">
              <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>
                {scanId?.length > 20 ? `${scanId.slice(0, 20)}...` : scanId}
              </span>
              <button onClick={handleCopyId}
                className="p-1 rounded hover:bg-white/5 transition-colors"
                title="Copy scan ID">
                {copied
                  ? <Check className="w-3.5 h-3.5 text-green-400" />
                  : <Copy className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />}
              </button>
            </div>
          </div>

          {/* Language tags */}
          {langs.length > 0 && (
            <div className="flex flex-wrap gap-1.5 ml-4">
              {langs.map(l => (
                <span key={l} className="text-xs px-2.5 py-1 rounded-full border bg-slate-500/10 text-slate-400 border-slate-500/20">
                  {l}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* KPI cards */}
        <div className="grid grid-cols-4 gap-x-4 gap-y-4 mb-6">
          <KpiCard
            title="Total Findings"
            value={normalizedFindings.length}
            subtitle={`From ${scan?.files_scanned || 0} files scanned`}
            icon={<ShieldAlert className="w-5 h-5" />}
            color={normalizedFindings.length > 0 ? 'orange' : 'green'}
          />
          <KpiCard
            title="Security Issues"
            value={securityFindings.length}
            subtitle="Exploitable vulnerabilities detected"
            icon={<AlertTriangle className="w-5 h-5" />}
            color={securityFindings.length > 0 ? 'red' : 'green'}
          />
          <KpiCard
            title="Files Scanned"
            value={scan?.files_scanned ?? '—'}
            subtitle={`${scan?.repo_url ? 'Repository scan' : 'Scan complete'}`}
            icon={<FileCode className="w-5 h-5" />}
            color="blue"
          />
          <KpiCard
            title="Languages"
            value={langs.length || allLanguages.length || '—'}
            subtitle={langs.slice(0, 2).join(', ') || 'Detected languages'}
            icon={<Code2 className="w-5 h-5" />}
            color="purple"
          />
        </div>

        {/* Donut + Top Rules row */}
        <div className="grid grid-cols-3 gap-x-4 gap-y-4 mb-6">
          <div className="col-span-1 rounded-2xl border overflow-hidden"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Security Severity</div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Distribution by severity level</div>
            </div>
            <div className="p-4">
              {donutData.length > 0
                ? <SeverityDonut data={donutData} totalLabel="Security" />
                : <div className="flex items-center justify-center h-32 text-sm" style={{ color: 'var(--text-tertiary)' }}>No security findings</div>
              }
            </div>
          </div>

          <div className="col-span-2 rounded-2xl border overflow-hidden"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Top Rules Triggered</div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Most frequent security rules</div>
            </div>
            <div className="p-4 space-y-2">
              {topRules.length === 0
                ? <div className="text-sm text-center py-6" style={{ color: 'var(--text-tertiary)' }}>No security rules triggered</div>
                : topRules.map(([rule, count], i) => {
                  const maxCount = topRules[0][1];
                  const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
                  return (
                    <div key={rule} className="flex items-center gap-3">
                      <span className="text-xs w-4 text-right font-mono" style={{ color: 'var(--text-tertiary)' }}>{i + 1}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-mono truncate" style={{ color: 'var(--text-primary)' }}>{rule}</span>
                          <span className="text-xs font-semibold ml-2 text-orange-400">{count}</span>
                        </div>
                        <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                          <div className="h-full bg-orange-500/70 rounded-full transition-all" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    </div>
                  );
                })
              }
            </div>
          </div>
        </div>

        {/* Tab strip */}
        <div className="flex items-center gap-1 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          {[
            { id: 'security', label: `Security Issues (${securityFindings.length})` },
            { id: 'quality',  label: `Code Quality (${codeQualityFindings.length})` },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === tab.id ? 'border-blue-500 text-blue-400' : 'border-transparent hover:opacity-75'
              }`}
              style={activeTab !== tab.id ? { color: 'var(--text-secondary)' } : {}}>
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="px-6 pt-5 pb-8 space-y-4">

        {/* Rule deep-link banner */}
        {ruleFilter && (
          <div className="flex items-center justify-between px-4 py-2.5 rounded-xl border border-blue-500/30 bg-blue-500/10">
            <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              Filtered to rule: <span className="font-mono font-semibold text-blue-400">{ruleFilter.replace(/_/g, ' ')}</span>
              <span className="ml-2 text-green-400 font-semibold">({filteredSecurity.length} match{filteredSecurity.length !== 1 ? 'es' : ''})</span>
            </div>
            <button
              onClick={() => router.push(`/secops/${scanId}`)}
              className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors">
              <X className="w-3.5 h-3.5" /> Clear filter
            </button>
          </div>
        )}

        {/* Security Issues tab */}
        {activeTab === 'security' && (
          <>
            <FilterBar
              filters={filterDefs}
              activeFilters={secFilters}
              onFilterChange={(key, val) => setSecFilters(prev => ({ ...prev, [key]: val }))}
            />
            <DataTable
              data={filteredSecurity}
              columns={findingColumns}
              pageSize={25}
              emptyMessage={ruleFilter ? `No findings for rule "${ruleFilter.replace(/_/g,' ')}"` : 'No security findings match the current filters.'}
              renderExpandedRow={(row) => <ExpandedFindingRow finding={{ _raw: row }} onOpenFix={setFixModalFinding} />}
            />
          </>
        )}

        {/* Code Quality tab */}
        {activeTab === 'quality' && (
          <>
            <FilterBar
              filters={filterDefs}
              activeFilters={cqFilters}
              onFilterChange={(key, val) => setCqFilters(prev => ({ ...prev, [key]: val }))}
            />
            <DataTable
              data={filteredCQ}
              columns={findingColumns}
              pageSize={25}
              emptyMessage="No code quality findings match the current filters."
              renderExpandedRow={(row) => <ExpandedFindingRow finding={{ _raw: row }} onOpenFix={setFixModalFinding} />}
            />
          </>
        )}
      </div>

      {/* How-to-Fix modal */}
      {fixModalFinding && (
        <FixModal
          finding={fixModalFinding}
          onClose={() => setFixModalFinding(null)}
        />
      )}
    </div>
  );
}
