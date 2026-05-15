/**
 * AWS service catalog — used by ScheduleModal service exclusion selection.
 * Maps service identifier → human-readable label.
 * Identifiers match what the discovery engine uses in rule_metadata.service.
 */

export interface AwsService {
  value: string;
  label: string;
  category: string;
}

export const AWS_SERVICES: AwsService[] = [
  // Compute
  { value: 'ec2',           label: 'EC2 (Virtual Machines)',       category: 'Compute' },
  { value: 'ecs',           label: 'ECS (Container Service)',       category: 'Compute' },
  { value: 'eks',           label: 'EKS (Kubernetes)',              category: 'Compute' },
  { value: 'lambda',        label: 'Lambda (Serverless)',           category: 'Compute' },
  { value: 'lightsail',     label: 'Lightsail',                    category: 'Compute' },
  { value: 'autoscaling',   label: 'Auto Scaling',                 category: 'Compute' },
  // Storage
  { value: 's3',            label: 'S3 (Object Storage)',          category: 'Storage' },
  { value: 'ebs',           label: 'EBS (Block Storage)',          category: 'Storage' },
  { value: 'efs',           label: 'EFS (File Storage)',           category: 'Storage' },
  { value: 'glacier',       label: 'Glacier (Archive)',            category: 'Storage' },
  { value: 'fsx',           label: 'FSx',                         category: 'Storage' },
  { value: 'backup',        label: 'AWS Backup',                   category: 'Storage' },
  // Database
  { value: 'rds',           label: 'RDS (Relational DB)',          category: 'Database' },
  { value: 'dynamodb',      label: 'DynamoDB (NoSQL)',             category: 'Database' },
  { value: 'elasticache',   label: 'ElastiCache',                 category: 'Database' },
  { value: 'redshift',      label: 'Redshift (Warehouse)',         category: 'Database' },
  { value: 'neptune',       label: 'Neptune (Graph DB)',           category: 'Database' },
  { value: 'documentdb',    label: 'DocumentDB',                  category: 'Database' },
  // Networking
  { value: 'vpc',           label: 'VPC (Virtual Network)',        category: 'Networking' },
  { value: 'elb',           label: 'ELB / ALB / NLB',             category: 'Networking' },
  { value: 'cloudfront',    label: 'CloudFront (CDN)',             category: 'Networking' },
  { value: 'route53',       label: 'Route 53 (DNS)',               category: 'Networking' },
  { value: 'apigateway',    label: 'API Gateway',                  category: 'Networking' },
  { value: 'directconnect', label: 'Direct Connect',               category: 'Networking' },
  { value: 'vpn',           label: 'VPN',                         category: 'Networking' },
  // Security
  { value: 'iam',           label: 'IAM (Identity & Access)',      category: 'Security' },
  { value: 'kms',           label: 'KMS (Key Management)',         category: 'Security' },
  { value: 'acm',           label: 'ACM (Certificates)',           category: 'Security' },
  { value: 'waf',           label: 'WAF (Web App Firewall)',       category: 'Security' },
  { value: 'shield',        label: 'Shield (DDoS)',                category: 'Security' },
  { value: 'guardduty',     label: 'GuardDuty',                   category: 'Security' },
  { value: 'securityhub',   label: 'Security Hub',                category: 'Security' },
  { value: 'inspector',     label: 'Inspector',                    category: 'Security' },
  { value: 'macie',         label: 'Macie (Data Security)',        category: 'Security' },
  // Monitoring & Logging
  { value: 'cloudtrail',    label: 'CloudTrail (Audit Logs)',      category: 'Monitoring' },
  { value: 'cloudwatch',    label: 'CloudWatch (Metrics/Logs)',    category: 'Monitoring' },
  { value: 'config',        label: 'AWS Config',                   category: 'Monitoring' },
  { value: 'accessanalyzer',label: 'IAM Access Analyzer',         category: 'Monitoring' },
  // Application Services
  { value: 'sns',           label: 'SNS (Notifications)',          category: 'Application' },
  { value: 'sqs',           label: 'SQS (Message Queue)',          category: 'Application' },
  { value: 'ses',           label: 'SES (Email)',                  category: 'Application' },
  { value: 'cognito',       label: 'Cognito (Auth)',               category: 'Application' },
  { value: 'secretsmanager',label: 'Secrets Manager',             category: 'Application' },
  { value: 'ssm',           label: 'Systems Manager (SSM)',        category: 'Application' },
  // AI / ML
  { value: 'sagemaker',     label: 'SageMaker (ML)',              category: 'AI/ML' },
  { value: 'bedrock',       label: 'Bedrock (GenAI)',             category: 'AI/ML' },
];

/** Flat list of service value strings (for quick set operations) */
export const AWS_SERVICE_VALUES: string[] = AWS_SERVICES.map(s => s.value);

/** Map value → label */
export const AWS_SERVICE_MAP: Record<string, string> = Object.fromEntries(
  AWS_SERVICES.map(s => [s.value, s.label]),
);

/** Services grouped by category */
export const AWS_SERVICES_BY_CATEGORY: Record<string, AwsService[]> = AWS_SERVICES.reduce(
  (acc, svc) => {
    if (!acc[svc.category]) acc[svc.category] = [];
    acc[svc.category].push(svc);
    return acc;
  },
  {} as Record<string, AwsService[]>,
);
