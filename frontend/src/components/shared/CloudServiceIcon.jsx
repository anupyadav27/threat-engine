/**
 * CloudServiceIcon — provider-accurate service icons for all major CSPs.
 *
 * Usage:
 *   <CloudServiceIcon service="S3Bucket" size={24} />
 *   <CloudServiceIcon service="AzureVM" provider="azure" size={20} />
 *
 * Service keys are normalised — accepts "S3Bucket", "S3 Bucket", "s3bucket",
 * "aws:s3", etc.  Falls back to a provider-coloured generic icon.
 */

// ── Brand colours ─────────────────────────────────────────────────────────────
export const PROVIDER_COLORS = {
  aws:     '#FF9900',
  azure:   '#0078D4',
  gcp:     '#4285F4',
  oci:     '#C74634',
  ibm:     '#0F62FE',
  k8s:     '#326CE5',
  generic: '#6366F1',
};

// ── Service colour map (overrides provider brand colour for specific services) ─
export const SERVICE_COLORS = {
  // AWS — storage
  S3Bucket:        '#FF9900',
  S3:              '#FF9900',
  // AWS — compute
  EC2Instance:     '#FF9900',
  EC2:             '#FF9900',
  Lambda:          '#FF9900',
  // AWS — database
  RDS:             '#527FFF',
  DynamoDBTable:   '#527FFF',
  DynamoDB:        '#527FFF',
  ElastiCache:     '#C7131F',
  // AWS — networking
  VPC:             '#8C4FFF',
  Subnet:          '#8C4FFF',
  SecurityGroup:   '#DD344C',
  NATGateway:      '#FF9900',
  CloudFront:      '#FF9900',
  VPCEndpoint:     '#8C4FFF',
  // AWS — security / IAM
  IAMRole:         '#DD344C',
  IAMUser:         '#DD344C',
  IAM:             '#DD344C',
  KMSKey:          '#DD344C',
  SecretsManager:  '#DD344C',
  // AWS — messaging
  SNSTopic:        '#FF4F8B',
  SQSQueue:        '#FF4F8B',
  // AWS — integration
  APIGateway:      '#FF9900',
  StepFunctions:   '#FF9900',
  // Azure
  AzureVM:         '#0078D4',
  AzureStorage:    '#0078D4',
  AzureSQL:        '#0078D4',
  AzureAD:         '#0078D4',
  AzureKeyVault:   '#0078D4',
  AzureAppService: '#0078D4',
  AzureLB:         '#0078D4',
  AzureVNet:       '#0078D4',
  AzureFunction:   '#0078D4',
  AzureContainer:  '#0078D4',
  // GCP
  GCPCompute:      '#EA4335',
  GCPStorage:      '#FBBC04',
  GCPSQL:          '#34A853',
  GCPFunction:     '#4285F4',
  GCPIAM:          '#EA4335',
  GCPGKECluster:   '#326CE5',
  GCPPubSub:       '#4285F4',
  // OCI
  OCICompute:      '#C74634',
  OCIStorage:      '#C74634',
  OCIDB:           '#C74634',
  // IBM
  IBMVirtualServer:'#0F62FE',
  IBMStorage:      '#0F62FE',
  // Kubernetes
  K8sPod:          '#326CE5',
  K8sDeployment:   '#326CE5',
  K8sService:      '#326CE5',
  K8sNamespace:    '#326CE5',
  K8sNode:         '#326CE5',
};

// ── SVG path definitions per service ─────────────────────────────────────────
// Each icon is drawn inside a 24×24 viewBox.

const ICONS = {
  /* ── AWS S3 ── */
  S3Bucket: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M12 3C7.6 3 4 4.8 4 7v10c0 2.2 3.6 4 8 4s8-1.8 8-4V7c0-2.2-3.6-4-8-4z" fill={c} opacity="0.9"/>
      <ellipse cx="12" cy="7" rx="8" ry="2.5" fill={c}/>
      <ellipse cx="12" cy="7" rx="8" ry="2.5" fill="white" opacity="0.25"/>
      <path d="M4 12c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5" stroke="white" strokeWidth="0.8" opacity="0.4"/>
    </svg>
  ),

  /* ── AWS EC2 ── */
  EC2Instance: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="3" y="5" width="18" height="14" rx="2" fill={c} opacity="0.9"/>
      <rect x="6" y="8" width="5" height="4" rx="0.5" fill="white" opacity="0.6"/>
      <rect x="13" y="8" width="5" height="4" rx="0.5" fill="white" opacity="0.6"/>
      <rect x="6" y="14" width="12" height="1.5" rx="0.5" fill="white" opacity="0.35"/>
      <circle cx="3" cy="8" r="1.2" fill={c}/>
      <circle cx="3" cy="12" r="1.2" fill={c}/>
      <circle cx="21" cy="8" r="1.2" fill={c}/>
      <circle cx="21" cy="12" r="1.2" fill={c}/>
    </svg>
  ),

  /* ── AWS Lambda ── */
  Lambda: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="2" y="2" width="20" height="20" rx="4" fill={c} opacity="0.9"/>
      <text x="12" y="17" textAnchor="middle" fill="white" fontSize="14" fontWeight="bold" fontFamily="serif">λ</text>
    </svg>
  ),

  /* ── AWS RDS ── */
  RDS: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <ellipse cx="12" cy="7" rx="8" ry="3" fill={c} opacity="0.9"/>
      <path d="M4 7v5c0 1.66 3.58 3 8 3s8-1.34 8-3V7" fill={c} opacity="0.75"/>
      <path d="M4 12v5c0 1.66 3.58 3 8 3s8-1.34 8-3v-5" fill={c} opacity="0.55"/>
      <ellipse cx="12" cy="7" rx="8" ry="3" fill="white" opacity="0.2"/>
    </svg>
  ),

  /* ── AWS DynamoDB ── */
  DynamoDBTable: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M12 3c-4 0-7 1.1-7 2.5v13C5 19.9 8 21 12 21s7-1.1 7-2.5v-13C19 4.1 16 3 12 3z" fill={c} opacity="0.85"/>
      <ellipse cx="12" cy="5.5" rx="7" ry="2" fill="white" opacity="0.3"/>
      <ellipse cx="12" cy="12" rx="7" ry="2" fill="white" opacity="0.2"/>
    </svg>
  ),

  /* ── AWS IAM Role ── */
  IAMRole: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="8" r="4" fill={c} opacity="0.9"/>
      <path d="M4 20c0-4.4 3.6-8 8-8s8 3.6 8 8" fill={c} opacity="0.7"/>
      <circle cx="17" cy="17" r="4" fill={c}/>
      <path d="M15.5 17l1 1.5 2.5-2.5" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),

  /* ── AWS IAM User ── */
  IAMUser: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="8" r="4.5" fill={c} opacity="0.9"/>
      <path d="M3 21c0-4.97 4.03-9 9-9s9 4.03 9 9" fill={c} opacity="0.7"/>
      <path d="M10 7.5l1.5 1.5L14 6.5" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),

  /* ── AWS Security Group ── */
  SecurityGroup: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M12 2L4 5.5v6c0 5.25 3.5 10.15 8 11.5C16.5 21.65 20 16.75 20 11.5v-6L12 2z" fill={c} opacity="0.9"/>
      <path d="M9 12l2 2 4-4" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),

  /* ── AWS VPC ── */
  VPC: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="2" y="2" width="20" height="20" rx="3" fill="none" stroke={c} strokeWidth="2"/>
      <rect x="6" y="6" width="5" height="5" rx="1.5" fill={c} opacity="0.7"/>
      <rect x="13" y="6" width="5" height="5" rx="1.5" fill={c} opacity="0.7"/>
      <rect x="6" y="13" width="5" height="5" rx="1.5" fill={c} opacity="0.7"/>
      <rect x="13" y="13" width="5" height="5" rx="1.5" fill={c} opacity="0.7"/>
      <line x1="11" y1="8.5" x2="13" y2="8.5" stroke={c} strokeWidth="1.5"/>
      <line x1="8.5" y1="11" x2="8.5" y2="13" stroke={c} strokeWidth="1.5"/>
      <line x1="15.5" y1="11" x2="15.5" y2="13" stroke={c} strokeWidth="1.5"/>
      <line x1="11" y1="15.5" x2="13" y2="15.5" stroke={c} strokeWidth="1.5"/>
    </svg>
  ),

  /* ── AWS Subnet ── */
  Subnet: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="3" y="3" width="18" height="18" rx="2" fill="none" stroke={c} strokeWidth="1.5" strokeDasharray="3 2"/>
      <rect x="7" y="7" width="10" height="10" rx="2" fill={c} opacity="0.7"/>
    </svg>
  ),

  /* ── AWS CloudFront ── */
  CloudFront: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="9" fill={c} opacity="0.15" stroke={c} strokeWidth="1.5"/>
      <ellipse cx="12" cy="12" rx="4" ry="9" fill="none" stroke={c} strokeWidth="1.5"/>
      <line x1="3" y1="12" x2="21" y2="12" stroke={c} strokeWidth="1.5"/>
      <path d="M5 7.5c2 1.5 4.5 2.5 7 2.5s5-1 7-2.5" stroke={c} strokeWidth="1.2" fill="none"/>
      <path d="M5 16.5c2-1.5 4.5-2.5 7-2.5s5 1 7 2.5" stroke={c} strokeWidth="1.2" fill="none"/>
    </svg>
  ),

  /* ── AWS NAT Gateway ── */
  NATGateway: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="2" y="8" width="20" height="8" rx="4" fill={c} opacity="0.85"/>
      <path d="M14 10l3 2-3 2" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M10 10l-3 2 3 2" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),

  /* ── AWS VPC Endpoint ── */
  VPCEndpoint: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="6" cy="12" r="4" fill={c} opacity="0.8"/>
      <circle cx="18" cy="12" r="4" fill={c} opacity="0.8"/>
      <path d="M10 12h4" stroke={c} strokeWidth="2" strokeDasharray="2 1"/>
      <circle cx="12" cy="12" r="2" fill={c}/>
    </svg>
  ),

  /* ── AWS KMS ── */
  KMSKey: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="9" cy="10" r="5" fill={c} opacity="0.85"/>
      <path d="M13 10h8M17 8v4" stroke={c} strokeWidth="2" strokeLinecap="round"/>
      <circle cx="9" cy="10" r="2.5" fill="white" opacity="0.4"/>
    </svg>
  ),

  /* ── AWS Secrets Manager ── */
  SecretsManager: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="5" y="11" width="14" height="10" rx="2" fill={c} opacity="0.85"/>
      <path d="M8 11V7a4 4 0 018 0v4" fill="none" stroke={c} strokeWidth="2"/>
      <circle cx="12" cy="16" r="2" fill="white" opacity="0.5"/>
    </svg>
  ),

  /* ── AWS SNS ── */
  SNSTopic: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0" stroke={c} strokeWidth="1.8" fill="none" strokeLinecap="round"/>
      <circle cx="12" cy="4" r="1.5" fill={c}/>
    </svg>
  ),

  /* ── AWS SQS ── */
  SQSQueue: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="3" y="5" width="18" height="4" rx="1.5" fill={c} opacity="0.9"/>
      <rect x="3" y="10" width="18" height="4" rx="1.5" fill={c} opacity="0.7"/>
      <rect x="3" y="15" width="18" height="4" rx="1.5" fill={c} opacity="0.5"/>
    </svg>
  ),

  /* ── AWS ElastiCache ── */
  ElastiCache: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M13 3L4 14h7l-2 7 9-11h-7l2-7z" fill={c} opacity="0.9"/>
    </svg>
  ),

  /* ── AWS API Gateway ── */
  APIGateway: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="2" y="8" width="8" height="8" rx="2" fill={c} opacity="0.85"/>
      <rect x="14" y="8" width="8" height="8" rx="2" fill={c} opacity="0.85"/>
      <path d="M10 12h4M12 10v4" stroke={c} strokeWidth="1.5" strokeLinecap="round"/>
    </svg>
  ),

  /* ── Azure Virtual Machine ── */
  AzureVM: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="2" y="4" width="20" height="14" rx="2" fill={c} opacity="0.85"/>
      <rect x="5" y="7" width="14" height="8" rx="1" fill="white" opacity="0.25"/>
      <rect x="8" y="18" width="8" height="2" rx="1" fill={c} opacity="0.7"/>
      <rect x="6" y="20" width="12" height="1" rx="0.5" fill={c} opacity="0.5"/>
    </svg>
  ),

  /* ── Azure Storage ── */
  AzureStorage: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M4 6h16l-2 14H6L4 6z" fill={c} opacity="0.85"/>
      <path d="M2 6h20" stroke={c} strokeWidth="2" strokeLinecap="round"/>
      <path d="M10 10v6M14 10v6" stroke="white" strokeWidth="1.2" opacity="0.5"/>
    </svg>
  ),

  /* ── Azure SQL ── */
  AzureSQL: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <ellipse cx="12" cy="6" rx="8" ry="3" fill={c} opacity="0.9"/>
      <path d="M4 6v12c0 1.66 3.58 3 8 3s8-1.34 8-3V6" fill={c} opacity="0.65"/>
      <path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3" stroke="white" strokeWidth="0.8" opacity="0.4"/>
      <text x="12" y="14" textAnchor="middle" fill="white" fontSize="6" fontWeight="bold">SQL</text>
    </svg>
  ),

  /* ── Azure Active Directory ── */
  AzureAD: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
    </svg>
  ),

  /* ── Azure Key Vault ── */
  AzureKeyVault: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.5C16.5 22.15 20 17.25 20 12V6l-8-4z" fill={c} opacity="0.85"/>
      <circle cx="10" cy="11" r="2.5" fill="white" opacity="0.5"/>
      <path d="M12 11h3M13.5 9.5v3" stroke="white" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  ),

  /* ── Azure Load Balancer ── */
  AzureLB: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="6" r="3" fill={c} opacity="0.9"/>
      <circle cx="6" cy="18" r="3" fill={c} opacity="0.75"/>
      <circle cx="18" cy="18" r="3" fill={c} opacity="0.75"/>
      <line x1="12" y1="9" x2="6" y2="15" stroke={c} strokeWidth="1.5"/>
      <line x1="12" y1="9" x2="18" y2="15" stroke={c} strokeWidth="1.5"/>
    </svg>
  ),

  /* ── Azure Virtual Network ── */
  AzureVNet: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="2" y="4" width="20" height="16" rx="2" fill="none" stroke={c} strokeWidth="1.5"/>
      <rect x="5" y="8" width="6" height="4" rx="1" fill={c} opacity="0.7"/>
      <rect x="13" y="8" width="6" height="4" rx="1" fill={c} opacity="0.7"/>
      <line x1="11" y1="10" x2="13" y2="10" stroke={c} strokeWidth="1.5"/>
    </svg>
  ),

  /* ── Azure Functions ── */
  AzureFunction: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="2" y="2" width="20" height="20" rx="3" fill={c} opacity="0.85"/>
      <text x="12" y="17" textAnchor="middle" fill="white" fontSize="13" fontWeight="bold">ƒ</text>
    </svg>
  ),

  /* ── GCP Compute Engine ── */
  GCPCompute: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="4" y="4" width="16" height="16" rx="2" fill={c} opacity="0.85"/>
      <rect x="7" y="7" width="10" height="10" rx="1" fill="white" opacity="0.25"/>
      <circle cx="12" cy="12" r="3" fill="white" opacity="0.4"/>
    </svg>
  ),

  /* ── GCP Cloud Storage ── */
  GCPStorage: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M19.35 10.04A7.49 7.49 0 0012 4C9.11 4 6.6 5.64 5.35 8.04A5.994 5.994 0 000 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z" fill={c} opacity="0.85"/>
    </svg>
  ),

  /* ── GCP Cloud SQL ── */
  GCPSQL: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <ellipse cx="12" cy="6" rx="7" ry="2.5" fill={c} opacity="0.9"/>
      <path d="M5 6v12c0 1.38 3.13 2.5 7 2.5s7-1.12 7-2.5V6" fill={c} opacity="0.65"/>
      <path d="M5 11c0 1.38 3.13 2.5 7 2.5s7-1.12 7-2.5" stroke="white" strokeWidth="0.8" opacity="0.4"/>
    </svg>
  ),

  /* ── GCP Cloud Functions ── */
  GCPFunction: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M15 3H9L7 9h4L8 21l9-12h-5l3-6z" fill={c} opacity="0.9"/>
    </svg>
  ),

  /* ── GCP IAM ── */
  GCPIAM: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="8" r="4.5" fill={c} opacity="0.9"/>
      <path d="M3 21c0-4.97 4.03-9 9-9s9 4.03 9 9" fill={c} opacity="0.65"/>
    </svg>
  ),

  /* ── GCP GKE ── */
  GCPGKECluster: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="3" fill={c}/>
      <circle cx="4" cy="6" r="2.5" fill={c} opacity="0.8"/>
      <circle cx="20" cy="6" r="2.5" fill={c} opacity="0.8"/>
      <circle cx="4" cy="18" r="2.5" fill={c} opacity="0.8"/>
      <circle cx="20" cy="18" r="2.5" fill={c} opacity="0.8"/>
      <line x1="9" y1="12" x2="6" y2="7.5" stroke={c} strokeWidth="1.2" opacity="0.6"/>
      <line x1="15" y1="12" x2="18" y2="7.5" stroke={c} strokeWidth="1.2" opacity="0.6"/>
      <line x1="9" y1="12" x2="6" y2="16.5" stroke={c} strokeWidth="1.2" opacity="0.6"/>
      <line x1="15" y1="12" x2="18" y2="16.5" stroke={c} strokeWidth="1.2" opacity="0.6"/>
    </svg>
  ),

  /* ── OCI Compute ── */
  OCICompute: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="3" y="6" width="18" height="12" rx="2" fill={c} opacity="0.85"/>
      <circle cx="8" cy="12" r="2.5" fill="white" opacity="0.4"/>
      <rect x="12" y="9" width="6" height="2" rx="1" fill="white" opacity="0.4"/>
      <rect x="12" y="13" width="4" height="2" rx="1" fill="white" opacity="0.4"/>
    </svg>
  ),

  /* ── OCI Storage ── */
  OCIStorage: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M4 8h16v10a2 2 0 01-2 2H6a2 2 0 01-2-2V8z" fill={c} opacity="0.85"/>
      <path d="M2 8h20" stroke={c} strokeWidth="2" strokeLinecap="round"/>
      <rect x="8" y="11" width="8" height="2" rx="1" fill="white" opacity="0.4"/>
    </svg>
  ),

  /* ── Kubernetes Pod ── */
  K8sPod: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <path d="M12 2l9 5v10l-9 5-9-5V7l9-5z" fill={c} opacity="0.85"/>
      <circle cx="12" cy="12" r="3" fill="white" opacity="0.4"/>
    </svg>
  ),

  /* ── Kubernetes Deployment ── */
  K8sDeployment: ({ c }) => (
    <svg viewBox="0 0 24 24" fill="none">
      <rect x="2" y="8" width="9" height="8" rx="2" fill={c} opacity="0.9"/>
      <rect x="13" y="8" width="9" height="8" rx="2" fill={c} opacity="0.6"/>
      <line x1="11" y1="12" x2="13" y2="12" stroke={c} strokeWidth="1.5"/>
    </svg>
  ),
};

// ── Icon aliases (normalise variants) ────────────────────────────────────────
const ALIASES = {
  s3: 'S3Bucket',
  's3 bucket': 'S3Bucket',
  's3bucket': 'S3Bucket',
  'aws:s3': 'S3Bucket',
  ec2: 'EC2Instance',
  'ec2 instance': 'EC2Instance',
  'ec2instance': 'EC2Instance',
  'aws:ec2': 'EC2Instance',
  lambda: 'Lambda',
  'aws:lambda': 'Lambda',
  rds: 'RDS',
  'rds database': 'RDS',
  'aws:rds': 'RDS',
  dynamodb: 'DynamoDBTable',
  'dynamodbtable': 'DynamoDBTable',
  'dynamodb table': 'DynamoDBTable',
  'aws:dynamodb': 'DynamoDBTable',
  'iam role': 'IAMRole',
  'iamrole': 'IAMRole',
  'aws:iam:role': 'IAMRole',
  'iam user': 'IAMUser',
  'iamuser': 'IAMUser',
  'aws:iam:user': 'IAMUser',
  iam: 'IAMRole',
  'security group': 'SecurityGroup',
  'securitygroup': 'SecurityGroup',
  'aws:ec2:securitygroup': 'SecurityGroup',
  sg: 'SecurityGroup',
  vpc: 'VPC',
  'aws:ec2:vpc': 'VPC',
  subnet: 'Subnet',
  'aws:ec2:subnet': 'Subnet',
  cloudfront: 'CloudFront',
  'aws:cloudfront': 'CloudFront',
  nat: 'NATGateway',
  'nat gateway': 'NATGateway',
  'natgateway': 'NATGateway',
  'vpc endpoint': 'VPCEndpoint',
  'vpcendpoint': 'VPCEndpoint',
  kms: 'KMSKey',
  'kms key': 'KMSKey',
  'kmskey': 'KMSKey',
  'aws:kms': 'KMSKey',
  secrets: 'SecretsManager',
  'secrets manager': 'SecretsManager',
  'secretsmanager': 'SecretsManager',
  'aws:secretsmanager': 'SecretsManager',
  sns: 'SNSTopic',
  'sns topic': 'SNSTopic',
  'snstopic': 'SNSTopic',
  sqs: 'SQSQueue',
  'sqs queue': 'SQSQueue',
  'sqsqueue': 'SQSQueue',
  elasticache: 'ElastiCache',
  'aws:elasticache': 'ElastiCache',
  apigateway: 'APIGateway',
  'api gateway': 'APIGateway',
  'aws:apigateway': 'APIGateway',
  // Azure
  'azure vm': 'AzureVM',
  'azurevm': 'AzureVM',
  'virtual machine': 'AzureVM',
  'azure storage': 'AzureStorage',
  'azurestorage': 'AzureStorage',
  'azure blob': 'AzureStorage',
  'azure sql': 'AzureSQL',
  'azuresql': 'AzureSQL',
  'azure ad': 'AzureAD',
  'azuread': 'AzureAD',
  'active directory': 'AzureAD',
  'azure key vault': 'AzureKeyVault',
  'azurekeyvault': 'AzureKeyVault',
  'azure lb': 'AzureLB',
  'azurelb': 'AzureLB',
  'azure load balancer': 'AzureLB',
  'azure vnet': 'AzureVNet',
  'azurevnet': 'AzureVNet',
  'azure function': 'AzureFunction',
  'azurefunction': 'AzureFunction',
  // GCP
  'gcp compute': 'GCPCompute',
  'gcpcompute': 'GCPCompute',
  'compute engine': 'GCPCompute',
  'gcp storage': 'GCPStorage',
  'gcpstorage': 'GCPStorage',
  'cloud storage': 'GCPStorage',
  'gcp sql': 'GCPSQL',
  'gcpsql': 'GCPSQL',
  'cloud sql': 'GCPSQL',
  'gcp function': 'GCPFunction',
  'gcpfunction': 'GCPFunction',
  'cloud functions': 'GCPFunction',
  'gcp iam': 'GCPIAM',
  'gcpiam': 'GCPIAM',
  'gke': 'GCPGKECluster',
  'gcpgkecluster': 'GCPGKECluster',
  // OCI
  'oci compute': 'OCICompute',
  'ocicompute': 'OCICompute',
  'oci storage': 'OCIStorage',
  'ocistorage': 'OCIStorage',
  // K8s
  pod: 'K8sPod',
  'k8s pod': 'K8sPod',
  deployment: 'K8sDeployment',
  'k8s deployment': 'K8sDeployment',
};

// ── Generic fallback icon (coloured circle with text) ─────────────────────────
function GenericIcon({ color, label }) {
  const abbr = (label || '?').toUpperCase().slice(0, 3);
  return (
    <svg viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" fill={color} opacity="0.85"/>
      <text x="12" y="16" textAnchor="middle" fill="white"
        fontSize={abbr.length === 1 ? 11 : abbr.length === 2 ? 9 : 7}
        fontWeight="bold" fontFamily="sans-serif">
        {abbr}
      </text>
    </svg>
  );
}

// ── Helper: resolve a service key ─────────────────────────────────────────────
function resolveKey(service) {
  if (!service) return null;
  const norm = service.toLowerCase().trim();
  return ALIASES[norm] || ALIASES[norm.replace(/\s+/g, '')] || service;
}

/**
 * CloudServiceIcon component.
 *
 * Props:
 *   service  {string} — service key e.g. "S3Bucket", "EC2Instance", "AzureVM"
 *   size     {number} — pixel size (default 24)
 *   className {string}
 *   style    {object}
 */
export default function CloudServiceIcon({ service, size = 24, className = '', style = {} }) {
  const key   = resolveKey(service);
  const color = SERVICE_COLORS[key] || PROVIDER_COLORS.generic;
  const Icon  = key && ICONS[key];

  return (
    <span
      className={className}
      style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: size, height: size, flexShrink: 0, ...style }}
    >
      {Icon
        ? <Icon c={color} />
        : <GenericIcon color={color} label={service} />
      }
    </span>
  );
}

/**
 * getServiceColor — returns the colour for a given service key.
 * Useful for canvas drawing (threat graph nodes).
 */
export function getServiceColor(service) {
  const key = resolveKey(service);
  return SERVICE_COLORS[key] || PROVIDER_COLORS.generic;
}
