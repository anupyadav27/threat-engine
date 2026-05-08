/**
 * Account type catalog — mirrors catalog/account_types/auth_requirements.yaml
 *
 * Bundled as static JS so client components can import without fs/yaml deps.
 * When the YAML changes, regenerate this file with:
 *   node scripts/generate-catalog.js
 */

export const CATALOG_VERSION = '1.0.0';

// ── Provider icon colors ────────────────────────────────────────────────────

export const PROVIDER_COLORS = {
  aws:         '#FF9900',
  azure:       '#0078D4',
  gcp:         '#4285F4',
  oci:         '#F80000',
  alicloud:    '#FF6A00',
  ibm:         '#1F70C1',
  k8s:         '#326CE5',
  github:      '#24292F',
  gitlab:      '#FC6D26',
  bitbucket:   '#0052CC',
  azure_devops:'#0078D4',
};

// ── Full account type catalog ───────────────────────────────────────────────

export const ACCOUNT_TYPES = [
  // ── AWS ──────────────────────────────────────────────────────────────────
  {
    id: 'aws', label: 'Amazon Web Services', tenant_type: 'cloud',
    provider: 'aws', icon: 'aws',
    auth_models: [
      {
        id: 'access_key', label: 'Access Key + Secret', auth_model: 'api_secret',
        recommended: false,
        description: 'IAM user with programmatic access. Suitable for single-account setups.',
        admin_prerequisites: [
          { step: 'Create an IAM user (or use an existing service user)', detail: 'IAM → Users → Add user → Programmatic access only' },
          { step: 'Attach the AWS-managed SecurityAudit policy to the user', detail: 'Policy ARN: arn:aws:iam::aws:policy/SecurityAudit' },
          { step: 'Attach the AWS-managed ReadOnlyAccess policy (optional)', detail: 'Policy ARN: arn:aws:iam::aws:policy/ReadOnlyAccess' },
          { step: 'Generate access key credentials', detail: 'IAM → User → Security credentials → Create access key → Copy Access Key ID + Secret' },
        ],
        credential_fields: [
          { name: 'access_key_id', label: 'Access Key ID', type: 'text', placeholder: 'AKIAIOSFODNN7EXAMPLE', required: true, sensitive: false },
          { name: 'secret_access_key', label: 'Secret Access Key', type: 'password', placeholder: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', required: true, sensitive: true },
        ],
      },
      {
        id: 'iam_role', label: 'IAM Role (Assume-Role)', auth_model: 'iam_role',
        recommended: true,
        description: 'Cross-account IAM role assumed by the CSPM platform. No long-lived secrets stored. Recommended for production.',
        admin_prerequisites: [
          { step: 'Create a cross-account IAM role in the target AWS account', detail: 'IAM → Roles → Create role → Another AWS account. Trusted account ID: 588989875114 (CSPM platform account). Add external ID shown in the wizard.' },
          { step: 'Attach the SecurityAudit managed policy to the role', detail: 'Policy ARN: arn:aws:iam::aws:policy/SecurityAudit' },
          { step: 'Copy the Role ARN from the role\'s summary page', detail: 'Format: arn:aws:iam::123456789012:role/CSPMAuditRole' },
          { step: '(Optional) Note the External ID you chose — paste it in the wizard', detail: 'Used to prevent confused deputy attacks' },
        ],
        credential_fields: [
          { name: 'role_arn', label: 'Role ARN', type: 'text', placeholder: 'arn:aws:iam::123456789012:role/CSPMAuditRole', required: true, sensitive: false },
          { name: 'external_id', label: 'External ID', type: 'text', placeholder: 'your-chosen-external-id', required: false, sensitive: false },
          { name: 'session_name', label: 'Session Name', type: 'text', placeholder: 'cspm-audit-session', required: false, sensitive: false },
        ],
      },
    ],
    scope_capabilities: { regions: true, services: true, exclude_services: true, engines: ['discovery','inventory','check','threat','compliance','iam','datasec','network','risk'] },
  },

  // ── Azure ─────────────────────────────────────────────────────────────────
  {
    id: 'azure', label: 'Microsoft Azure', tenant_type: 'cloud',
    provider: 'azure', icon: 'azure',
    auth_models: [
      {
        id: 'service_principal', label: 'Service Principal (Client Secret)', auth_model: 'api_secret',
        recommended: true,
        description: 'Azure App Registration with a client secret. Grants CSPM read-only access to an Azure subscription.',
        admin_prerequisites: [
          { step: 'Register an app in Azure Active Directory', detail: 'Azure Portal → Azure Active Directory → App registrations → New registration → Name: CSPM-Audit → Single tenant' },
          { step: 'Create a client secret for the app registration', detail: 'App registration → Certificates & secrets → New client secret → Set expiry → Copy the secret value immediately (shown once)' },
          { step: 'Note the Application (client) ID and Directory (tenant) ID', detail: 'Shown on the app registration Overview page' },
          { step: 'Assign the Reader role to the app on the target subscription', detail: 'Subscriptions → {your subscription} → Access control (IAM) → Add role assignment → Reader → Assign to: your app registration' },
          { step: 'Note the Subscription ID', detail: 'Subscriptions → {your subscription} → Subscription ID' },
        ],
        credential_fields: [
          { name: 'client_id', label: 'Application (Client) ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', required: true, sensitive: false },
          { name: 'client_secret', label: 'Client Secret', type: 'password', placeholder: 'your-client-secret-value', required: true, sensitive: true },
          { name: 'tenant_id', label: 'Directory (Tenant) ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', required: true, sensitive: false },
          { name: 'subscription_id', label: 'Subscription ID', type: 'text', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', required: true, sensitive: false },
        ],
      },
    ],
    scope_capabilities: { regions: true, services: true, exclude_services: true, engines: ['discovery','inventory','check','threat','compliance','iam','datasec','network','risk'] },
  },

  // ── GCP ──────────────────────────────────────────────────────────────────
  {
    id: 'gcp', label: 'Google Cloud Platform', tenant_type: 'cloud',
    provider: 'gcp', icon: 'gcp',
    auth_models: [
      {
        id: 'service_account_json', label: 'Service Account JSON Key', auth_model: 'file_upload',
        recommended: true,
        description: 'GCP service account with a JSON key file. Upload the downloaded JSON file directly.',
        admin_prerequisites: [
          { step: 'Create a service account in the target GCP project', detail: 'GCP Console → IAM & Admin → Service Accounts → Create → Name: cspm-audit-sa → Create and continue' },
          { step: 'Grant the Viewer role to the service account on the project', detail: 'IAM & Admin → IAM → Add principal → your service account email → Role: Viewer (or Security Reviewer for deeper access)' },
          { step: 'Create and download a JSON key for the service account', detail: 'Service Accounts → select account → Keys → Add Key → JSON → Download the .json file' },
        ],
        credential_fields: [
          { name: 'service_account_json', label: 'Service Account JSON Key File', type: 'file', accept: '.json', required: true, sensitive: true },
        ],
      },
    ],
    scope_capabilities: { regions: true, services: true, exclude_services: true, engines: ['discovery','inventory','check','threat','compliance','iam','datasec','network','risk'] },
  },

  // ── OCI ──────────────────────────────────────────────────────────────────
  {
    id: 'oci', label: 'Oracle Cloud Infrastructure', tenant_type: 'cloud',
    provider: 'oci', icon: 'oci',
    auth_models: [
      {
        id: 'config_file', label: 'OCI Config + API Key', auth_model: 'file_upload',
        recommended: true,
        description: 'OCI user with an API signing key. Upload the private key file and enter config values.',
        admin_prerequisites: [
          { step: 'Create or use an existing OCI IAM user for CSPM scanning', detail: 'Identity & Security → Users → Create user' },
          { step: 'Generate an API signing key pair', detail: 'User Details → API keys → Add API key → Generate API key pair → Download private key' },
          { step: 'Copy the Configuration File Preview shown after adding the key', detail: 'Contains tenancy OCID, user OCID, fingerprint, region' },
          { step: 'Assign the ReadOnlyAccess policy to the user in the target compartment', detail: 'Policies → Create policy → Allow group <group> to inspect all-resources in tenancy' },
        ],
        credential_fields: [
          { name: 'tenancy_ocid', label: 'Tenancy OCID', type: 'text', placeholder: 'ocid1.tenancy.oc1..aaa...', required: true, sensitive: false },
          { name: 'user_ocid', label: 'User OCID', type: 'text', placeholder: 'ocid1.user.oc1..aaa...', required: true, sensitive: false },
          { name: 'fingerprint', label: 'Key Fingerprint', type: 'text', placeholder: 'xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx', required: true, sensitive: false },
          { name: 'region', label: 'Home Region', type: 'text', placeholder: 'us-ashburn-1', required: true, sensitive: false },
          { name: 'private_key_file', label: 'Private Key File (.pem)', type: 'file', accept: '.pem', required: true, sensitive: true },
        ],
      },
    ],
    scope_capabilities: { regions: true, services: true, exclude_services: true, engines: ['discovery','inventory','check','threat','compliance','iam','datasec','network','risk'] },
  },

  // ── AliCloud ──────────────────────────────────────────────────────────────
  {
    id: 'alicloud', label: 'Alibaba Cloud', tenant_type: 'cloud',
    provider: 'alicloud', icon: 'alicloud',
    auth_models: [
      {
        id: 'access_key', label: 'Access Key + Secret', auth_model: 'api_secret',
        recommended: true,
        description: 'Alibaba Cloud RAM user with read-only permissions.',
        admin_prerequisites: [
          { step: 'Create a RAM user for CSPM scanning', detail: 'RAM console → Users → Create User → Programmatic Access only' },
          { step: 'Attach the ReadOnlyAccess system policy', detail: 'RAM → Policies → Attach → ReadOnlyAccess to the RAM user' },
          { step: 'Create an Access Key for the RAM user', detail: 'RAM User → Create AccessKey → Copy ID and Secret' },
        ],
        credential_fields: [
          { name: 'access_key_id', label: 'Access Key ID', type: 'text', placeholder: 'LTAI5t...', required: true, sensitive: false },
          { name: 'access_key_secret', label: 'Access Key Secret', type: 'password', placeholder: 'your-secret', required: true, sensitive: true },
          { name: 'region_id', label: 'Default Region', type: 'text', placeholder: 'cn-hangzhou', required: true, sensitive: false },
        ],
      },
    ],
    scope_capabilities: { regions: true, services: true, exclude_services: true, engines: ['discovery','inventory','check','threat','compliance','iam','datasec','network','risk'] },
  },

  // ── IBM Cloud ─────────────────────────────────────────────────────────────
  {
    id: 'ibm', label: 'IBM Cloud', tenant_type: 'cloud',
    provider: 'ibm', icon: 'ibm',
    auth_models: [
      {
        id: 'api_key', label: 'IBM Cloud API Key', auth_model: 'api_secret',
        recommended: true,
        description: 'IBM Cloud IAM API key with Viewer role on account resources.',
        admin_prerequisites: [
          { step: 'Create an IBM Cloud API key', detail: 'IBM Cloud Console → Manage → Access (IAM) → API keys → Create → Copy key' },
          { step: 'Assign the Viewer platform role to the key on all services', detail: 'IAM → Access groups → Create group → Add Viewer access → Add the API key user' },
        ],
        credential_fields: [
          { name: 'api_key', label: 'IBM Cloud API Key', type: 'password', placeholder: 'your-ibm-api-key', required: true, sensitive: true },
        ],
      },
    ],
    scope_capabilities: { regions: true, services: true, exclude_services: true, engines: ['discovery','inventory','check','threat','compliance','iam','datasec','network','risk'] },
  },

  // ── Kubernetes (kubeconfig) ───────────────────────────────────────────────
  {
    id: 'k8s_kubeconfig', label: 'Kubernetes (kubeconfig)', tenant_type: 'cloud',
    provider: 'k8s', icon: 'k8s',
    auth_models: [
      {
        id: 'kubeconfig', label: 'kubeconfig File', auth_model: 'file_upload',
        recommended: true,
        description: 'Upload a kubeconfig file with read-only cluster access.',
        admin_prerequisites: [
          { step: 'Create a read-only service account in the cluster', detail: 'kubectl create serviceaccount cspm-audit -n default' },
          { step: 'Create a ClusterRole with read-only permissions', detail: 'kubectl apply -f cspm-clusterrole.yaml (role provided in docs)' },
          { step: 'Bind the ClusterRole to the service account', detail: 'kubectl create clusterrolebinding cspm-binding --clusterrole=cspm-audit-role --serviceaccount=default:cspm-audit' },
          { step: 'Export a kubeconfig for the service account', detail: 'kubectl config view --minify --flatten > cspm-kubeconfig.yaml' },
        ],
        credential_fields: [
          { name: 'kubeconfig', label: 'kubeconfig File', type: 'file', accept: '.yaml,.yml,.json', required: true, sensitive: true },
        ],
      },
    ],
    scope_capabilities: { regions: false, services: true, engines: ['discovery','inventory','check','threat','compliance','container_security'] },
  },

  // ── GitHub ────────────────────────────────────────────────────────────────
  {
    id: 'github', label: 'GitHub', tenant_type: 'secops',
    provider: 'github', icon: 'github',
    auth_models: [
      {
        id: 'pat', label: 'Personal Access Token', auth_model: 'git_token',
        recommended: false,
        description: 'GitHub PAT with repo read access for SAST/IaC scanning.',
        admin_prerequisites: [
          { step: 'Create a GitHub Personal Access Token', detail: 'GitHub → Settings → Developer settings → Personal access tokens (classic) → Scopes: repo (read), read:org' },
        ],
        credential_fields: [
          { name: 'token', label: 'Personal Access Token', type: 'password', required: true, sensitive: true },
          { name: 'repo_url', label: 'Repository URL', type: 'text', placeholder: 'https://github.com/org/repo', required: true, sensitive: false },
        ],
      },
      {
        id: 'github_app', label: 'GitHub App', auth_model: 'git_token',
        recommended: true,
        description: 'GitHub App installation — preferred for org-level access without personal tokens.',
        admin_prerequisites: [
          { step: 'Install the CSPM GitHub App on your organization', detail: 'GitHub → Settings → Applications → Install the CSPM scanning app → Grant repo read access' },
          { step: 'Note the Installation ID shown after installation', detail: 'Visible in the app installation URL' },
        ],
        credential_fields: [
          { name: 'installation_id', label: 'App Installation ID', type: 'text', placeholder: '12345678', required: true, sensitive: false },
          { name: 'repo_url', label: 'Repository URL', type: 'text', placeholder: 'https://github.com/org/repo or git@github.com:org/repo.git', required: true, sensitive: false },
        ],
      },
    ],
    scope_capabilities: { regions: false, services: false, branches: true, engines: ['secops'] },
  },

  // ── GitLab ────────────────────────────────────────────────────────────────
  {
    id: 'gitlab', label: 'GitLab', tenant_type: 'secops',
    provider: 'gitlab', icon: 'gitlab',
    auth_models: [
      {
        id: 'deploy_token', label: 'Deploy Token (Repository)', auth_model: 'git_token',
        recommended: true,
        description: 'GitLab deploy token for repository-level read access.',
        admin_prerequisites: [
          { step: 'Create a GitLab Deploy Token on the project', detail: 'Project → Settings → Repository → Deploy tokens → Name: cspm-scanner, Scopes: read_repository' },
          { step: 'Copy the username and token value', detail: 'Shown only once on creation' },
        ],
        credential_fields: [
          { name: 'username', label: 'Deploy Token Username', type: 'text', required: true, sensitive: false },
          { name: 'token', label: 'Deploy Token', type: 'password', required: true, sensitive: true },
          { name: 'repo_url', label: 'Repository URL', type: 'text', placeholder: 'https://gitlab.com/group/project', required: true, sensitive: false },
        ],
      },
      {
        id: 'pat', label: 'Personal Access Token', auth_model: 'git_token',
        recommended: false,
        description: 'GitLab PAT with read_repository and read_api scopes.',
        admin_prerequisites: [
          { step: 'Create a GitLab Personal Access Token', detail: 'GitLab → User Settings → Access Tokens → Scopes: read_repository, read_api' },
        ],
        credential_fields: [
          { name: 'token', label: 'Personal Access Token', type: 'password', required: true, sensitive: true },
          { name: 'repo_url', label: 'Repository URL', type: 'text', placeholder: 'https://gitlab.com/group/project', required: true, sensitive: false },
        ],
      },
    ],
    scope_capabilities: { regions: false, branches: true, engines: ['secops'] },
  },

  // ── Bitbucket ─────────────────────────────────────────────────────────────
  {
    id: 'bitbucket', label: 'Bitbucket', tenant_type: 'secops',
    provider: 'bitbucket', icon: 'bitbucket',
    auth_models: [
      {
        id: 'app_password', label: 'App Password', auth_model: 'git_token',
        recommended: true,
        description: 'Bitbucket App Password with Repositories: Read permission.',
        admin_prerequisites: [
          { step: 'Create a Bitbucket App Password', detail: 'Bitbucket → Personal settings → App passwords → Create → Permissions: Repositories: Read' },
        ],
        credential_fields: [
          { name: 'username', label: 'Bitbucket Username', type: 'text', required: true, sensitive: false },
          { name: 'app_password', label: 'App Password', type: 'password', required: true, sensitive: true },
          { name: 'repo_url', label: 'Repository URL', type: 'text', placeholder: 'https://bitbucket.org/workspace/repo', required: true, sensitive: false },
        ],
      },
    ],
    scope_capabilities: { regions: false, branches: true, engines: ['secops'] },
  },

  // ── Azure DevOps ──────────────────────────────────────────────────────────
  {
    id: 'azure_devops', label: 'Azure DevOps', tenant_type: 'secops',
    provider: 'azure_devops', icon: 'azure_devops',
    auth_models: [
      {
        id: 'pat', label: 'Personal Access Token', auth_model: 'git_token',
        recommended: true,
        description: 'Azure DevOps PAT with Code (Read) scope.',
        admin_prerequisites: [
          { step: 'Create an Azure DevOps PAT', detail: 'Azure DevOps → User Settings → Personal access tokens → New Token → Scopes: Code (Read)' },
        ],
        credential_fields: [
          { name: 'organization', label: 'Organization Name', type: 'text', placeholder: 'your-org', required: true, sensitive: false },
          { name: 'project', label: 'Project Name', type: 'text', required: true, sensitive: false },
          { name: 'token', label: 'Personal Access Token', type: 'password', required: true, sensitive: true },
        ],
      },
    ],
    scope_capabilities: { regions: false, branches: true, engines: ['secops'] },
  },

  // ── Vulnerability Agent ───────────────────────────────────────────────────
  {
    id: 'vulnerability_agent', label: 'Vulnerability Agent', tenant_type: 'vulnerability',
    provider: 'agent', icon: 'agent', is_agent: true,
    auth_models: [
      {
        id: 'agent', label: 'Vulnerability Agent', auth_model: 'agent',
        recommended: true,
        description: 'Install the CSPM Vulnerability Agent on the target system. No cloud credentials required.',
        admin_prerequisites: [
          { step: 'Ensure the target system has outbound HTTPS (port 443) access to the CSPM platform', detail: 'The agent needs to reach the onboarding engine API to register and post results' },
          { step: 'Ensure you have sudo/root access on the target system for installation', detail: 'The agent installer requires elevated privileges to install as a system service' },
          { step: 'Note the target system\'s OS (Linux/Windows/macOS) — installer command varies' },
        ],
        credential_fields: [],
        agent_install: {
          show_install_command: true,
          bootstrap_ttl_minutes: 15,
          validation: 'agent_heartbeat',
          platforms: [
            { os: 'linux', command: 'curl -sSL https://install.cspm.io/vuln-agent | sudo bash \\\n  --registration-id {registration_id} \\\n  --verifier {code_verifier}' },
            { os: 'docker', command: 'docker run -d --name cspm-vuln-agent \\\n  -e REGISTRATION_ID={registration_id} \\\n  -e CODE_VERIFIER={code_verifier} \\\n  yadavanup84/cspm-vuln-agent:latest' },
          ],
        },
      },
    ],
    scope_capabilities: { regions: false, services: false, engines: ['vulnerability'] },
  },

  // ── Database Agent ────────────────────────────────────────────────────────
  {
    id: 'database_agent', label: 'Database Agent', tenant_type: 'database',
    provider: 'agent', icon: 'database', is_agent: true,
    auth_models: [
      {
        id: 'agent', label: 'Database Security Agent', auth_model: 'agent',
        recommended: true,
        description: 'Install the CSPM Database Agent on the target host. No cloud credentials required.',
        admin_prerequisites: [
          { step: 'Ensure the target host has outbound HTTPS (port 443) access to the CSPM platform' },
          { step: 'Ensure you have sudo/root access on the target host' },
          { step: 'Note the database engine type (PostgreSQL, MySQL, MSSQL, MongoDB, Oracle)' },
        ],
        credential_fields: [],
        agent_install: {
          show_install_command: true,
          bootstrap_ttl_minutes: 15,
          validation: 'agent_heartbeat',
          platforms: [
            { os: 'linux', command: 'curl -sSL https://install.cspm.io/db-agent | sudo bash \\\n  --registration-id {registration_id} \\\n  --verifier {code_verifier}' },
            { os: 'docker', command: 'docker run -d --name cspm-db-agent \\\n  -e REGISTRATION_ID={registration_id} \\\n  -e CODE_VERIFIER={code_verifier} \\\n  yadavanup84/cspm-db-agent:latest' },
          ],
        },
      },
    ],
    scope_capabilities: { regions: false, services: false, engines: ['dbsec'] },
  },

  // ── Middleware Agent ──────────────────────────────────────────────────────
  {
    id: 'middleware_agent', label: 'Middleware Agent', tenant_type: 'middleware',
    provider: 'agent', icon: 'middleware', is_agent: true,
    auth_models: [
      {
        id: 'agent', label: 'Middleware Security Agent', auth_model: 'agent',
        recommended: true,
        description: 'Install the CSPM Middleware Agent for application middleware security monitoring.',
        admin_prerequisites: [
          { step: 'Ensure the target host has outbound HTTPS (port 443) access to the CSPM platform' },
          { step: 'Ensure you have access to the middleware service configuration' },
          { step: 'Note the middleware type (Nginx, Apache, Tomcat, etc.)' },
        ],
        credential_fields: [],
        agent_install: {
          show_install_command: true,
          bootstrap_ttl_minutes: 15,
          validation: 'agent_heartbeat',
          platforms: [
            { os: 'linux', command: 'curl -sSL https://install.cspm.io/middleware-agent | sudo bash \\\n  --registration-id {registration_id} \\\n  --verifier {code_verifier}' },
          ],
        },
      },
    ],
    scope_capabilities: { regions: false, services: false, engines: ['check'] },
  },
];

// ── Helper functions ────────────────────────────────────────────────────────

export function getAccountTypeById(id) {
  return ACCOUNT_TYPES.find(a => a.id === id) || null;
}

export function getAccountTypesByTenantType(tenantType) {
  return ACCOUNT_TYPES.filter(a => a.tenant_type === tenantType);
}

export function getAuthModelById(accountTypeId, authModelId) {
  const at = getAccountTypeById(accountTypeId);
  return at?.auth_models?.find(m => m.id === authModelId) || null;
}

export function isAgentType(accountTypeId) {
  const at = getAccountTypeById(accountTypeId);
  return at?.is_agent === true;
}

export function getProviderColor(provider) {
  return PROVIDER_COLORS[provider] || '#6366f1';
}

// Groups by tenant_type for wizard technology grid display
export const CATALOG_BY_TENANT_TYPE = ACCOUNT_TYPES.reduce((acc, at) => {
  if (!acc[at.tenant_type]) acc[at.tenant_type] = [];
  acc[at.tenant_type].push(at);
  return acc;
}, {});
