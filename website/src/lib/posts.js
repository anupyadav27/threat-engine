export const posts = [
  {
    slug: 'cloud-misconfiguration-top-attack-vector-2026',
    title: 'Cloud Misconfiguration: The #1 Attack Vector in 2026',
    excerpt: 'Over 82% of cloud breaches trace back to a single root cause: misconfiguration. We dive deep into the most dangerous misconfigs across AWS, Azure, and GCP — and how to fix them before attackers find them.',
    category: 'Threat Intelligence',
    categoryColor: '#ef4444',
    author: 'Anup Yadav',
    authorTitle: 'Founder & Head of Security Research',
    date: 'March 5, 2026',
    readTime: '9 min read',
    tags: ['CSPM', 'Misconfiguration', 'AWS', 'Azure', 'GCP'],
    featured: true,
    content: `
Cloud misconfiguration has quietly become the most significant attack vector in modern infrastructure — not ransomware, not zero-days, not supply chain attacks. According to our analysis of over 3,900 security findings across 500+ cloud accounts, **82% of critical findings trace back to misconfiguration** rather than software vulnerabilities.

This isn't new information. The challenge is that despite years of awareness, misconfigurations remain stubbornly common. Here's why — and what to do about it.

## Why Misconfiguration Persists

The cloud's promise of speed and self-service is also its security Achilles heel. Developers can spin up infrastructure in minutes, often without security review. IAM policies get permissive "just to make it work." S3 buckets get set to public "temporarily." Security groups open port 0.0.0.0/0 and never get cleaned up.

Three structural forces keep misconfiguration rates high:

**1. The Complexity Tax**
AWS alone has over 200 services, each with its own configuration model. Azure adds another 100+. GCP brings more. A single modern cloud workload might span 15+ services — each a potential misconfiguration point. No team can manually audit that surface area.

**2. Configuration Drift**
Cloud configurations are living things. A resource compliant today may be misconfigured tomorrow after a routine change, a new team member's experiment, or an automated process gone wrong. Point-in-time audits are fundamentally insufficient.

**3. The Shared Responsibility Confusion**
Cloud providers secure *the* cloud. You're responsible for *your* cloud configuration. This line is clear in theory and blurry in practice. Teams routinely assume their cloud provider's defaults are secure. They rarely are.

## The Top 10 Misconfigurations We See in the Wild

In our analysis of cloud environments, these are the most dangerous and most common:

### 1. Public S3 Buckets with Sensitive Data
The classic. Despite AWS adding multiple safeguards, we still find publicly accessible S3 buckets containing credentials, PII, and internal documentation. The fix: enable \`BlockPublicAcls\`, \`BlockPublicPolicy\`, \`IgnorePublicAcls\`, and \`RestrictPublicBuckets\` at the account level — not just the bucket level.

### 2. Overly Permissive IAM Roles
\`AdministratorAccess\` attached to Lambda functions, EC2 instance profiles with \`*:*\` permissions, service accounts that can assume any role. Least-privilege in principle, wildcard in practice.

### 3. Unencrypted Data at Rest
RDS instances, S3 buckets, EBS volumes, DynamoDB tables — all storing sensitive data without encryption. Encryption is free. The operational overhead is minimal. There's no excuse in 2026.

### 4. Missing MFA on Root Accounts
The AWS root account has unrestricted access to every resource. Leaving it without hardware MFA is equivalent to leaving your master key under the doormat.

### 5. Security Groups Open to 0.0.0.0/0
Port 22 (SSH), 3389 (RDP), and 5432 (PostgreSQL) exposed to the entire internet. Seen in 34% of the accounts we scan.

### 6. CloudTrail Disabled or Misconfigured
Without CloudTrail, you're flying blind. Even when enabled, teams often miss multi-region coverage, log file validation, and S3 access logging for the CloudTrail bucket itself.

### 7. No VPC Flow Logs
Flow logs are your network audit trail. Without them, you have no visibility into lateral movement, data exfiltration, or unusual traffic patterns.

### 8. Unrestricted Egress
Outbound traffic controls are an afterthought. Data exfiltration is often invisible until it's too late. Egress filtering is not just about compliance — it's your last line of defense.

### 9. Default Network ACLs
Out-of-the-box network ACLs permit all traffic. They're frequently left at defaults because teams don't understand their interaction with security groups.

### 10. Publicly Accessible RDS Instances
Databases accessible from the internet with default credentials. We find these in 12% of the accounts we scan. 12% of databases — containing your customers' data — accessible to anyone.

## The CSPM Approach: Continuous, Not Periodic

The answer isn't more manual audits. It's continuous automated assessment.

A modern CSPM platform should:

- **Scan continuously** — not quarterly, not on-demand. Every new resource, every configuration change, evaluated in real time.
- **Map to frameworks** — findings should automatically map to CIS Benchmarks, NIST CSF, PCI-DSS, and others. Compliance shouldn't require a separate tool.
- **Prioritize by risk** — a public S3 bucket in production is not the same risk as one in a dev sandbox. Context matters.
- **Track drift** — show you what changed between yesterday and today.
- **Integrate with remediation** — findings should feed directly into your ticketing system, with auto-remediation for high-confidence, low-risk fixes.

## Looking Forward: AI-Assisted Misconfiguration Detection

The next frontier is using machine learning to identify *novel* misconfigurations — configurations that aren't in any rule database but are unusual enough to warrant investigation. This includes:

- Unusual permission grant patterns
- Configurations that deviate from your organization's baseline
- Cross-account relationships that create unexpected attack paths

We're building exactly this capability into Threat Engine. The goal isn't just to tell you what's wrong — it's to show you what's about to go wrong before it does.

---

*Anup Yadav is the founder of Threat Engine and a CSPM researcher with 12+ years in cloud security. He has presented at AWS re:Invent, CloudSecNext, and RSA Conference.*
    `,
  },
  {
    slug: 'mitre-attack-cloud-threat-mapping',
    title: 'MITRE ATT&CK for Cloud: Mapping Attack Chains Across Multi-Cloud Environments',
    excerpt: 'MITRE ATT&CK Enterprise now includes detailed cloud-specific techniques. Learn how to use this framework to build detection coverage, measure your posture, and understand real attack chains that target AWS, Azure, and GCP.',
    category: 'MITRE ATT&CK',
    categoryColor: '#8b5cf6',
    author: 'Anup Yadav',
    authorTitle: 'Founder & Head of Security Research',
    date: 'February 28, 2026',
    readTime: '11 min read',
    tags: ['MITRE', 'ATT&CK', 'Threat Detection', 'Multi-Cloud'],
    featured: true,
    content: `
The MITRE ATT&CK framework has fundamentally changed how security teams think about adversary behavior. Since adding cloud-specific techniques in 2019, the framework has become the de facto standard for structuring threat intelligence in cloud environments. Yet most organizations use it poorly — as a checkbox exercise rather than an operational tool.

This post covers how to actually operationalize ATT&CK for cloud, mapped to what we observe across real cloud environments.

## The ATT&CK Cloud Matrix: What's in It

The ATT&CK Enterprise matrix includes a Cloud (IaaS) sub-matrix with coverage across AWS, Azure, GCP, and others. As of v15, it includes **14 tactics** and **over 80 cloud-specific techniques**.

The tactical progression mirrors the general enterprise matrix:

1. **Reconnaissance** — Gathering info about cloud services, IP ranges, exposed endpoints
2. **Resource Development** — Staging infrastructure for attacks
3. **Initial Access** — Valid Accounts (T1078), Exploit Public-Facing Application (T1190)
4. **Execution** — Cloud Administration Command (T1651), Serverless Execution (T1648)
5. **Persistence** — Account Manipulation (T1098), Implant Internal Image (T1525)
6. **Privilege Escalation** — Cloud Service Dashboard (T1538), Valid Accounts (T1078)
7. **Defense Evasion** — Impair Defenses (T1562), Modify Cloud Compute Infrastructure (T1578)
8. **Credential Access** — Unsecured Credentials (T1552), Cloud Instance Metadata API (T1552.005)
9. **Discovery** — Cloud Service Discovery (T1526), Cloud Storage Object Discovery (T1619)
10. **Lateral Movement** — Internal Spearphishing (T1534), Use Alternate Authentication Material (T1550)
11. **Collection** — Data from Cloud Storage (T1530)
12. **Exfiltration** — Transfer Data to Cloud Account (T1537)
13. **Impact** — Financial Theft (T1657), Resource Hijacking (T1496)

## The Most Dangerous Cloud Attack Chains

Individual techniques are less important than **attack chains** — sequences of techniques that combine into a realistic breach scenario.

### Chain 1: The Credential Harvest → Privilege Escalation → Exfiltration Path

This is the most common attack chain we observe in IR engagements:

1. **T1552.005** — Attacker gains initial access to a compromised EC2 instance and queries the instance metadata service (IMDS): \`http://169.254.169.254/latest/meta-data/iam/security-credentials/\`
2. **T1098** — Uses the harvested credentials to create a new IAM user with administrative permissions
3. **T1078** — Authenticates as the new user (now with persistent access)
4. **T1530** — Discovers and exfiltrates data from S3 buckets
5. **T1537** — Transfers data to an attacker-controlled AWS account using S3 cross-account replication

**Detection points:**
- IMDS queries from unusual processes (T1552.005)
- IAM user creation followed immediately by privilege escalation (T1098)
- S3 cross-account data copy to unknown accounts (T1537)

### Chain 2: The Publicly Exposed Workload → Persistence

1. **T1190** — Exploit a vulnerability in a publicly exposed containerized service
2. **T1525** — Implant a malicious container image in ECR for persistence
3. **T1651** — Execute commands via AWS Systems Manager for command-and-control
4. **T1496** — Mine cryptocurrency using compromised compute resources

### Chain 3: The Insider Threat / Lateral Movement

1. **T1078** — Compromised employee credentials (phishing, credential stuffing)
2. **T1538** — Use Cloud Service Dashboard to understand account topology
3. **T1526** — Enumerate services, resources, and IAM roles across the environment
4. **T1550** — Use SSO tokens to pivot to other AWS accounts in an organization

## Building Detection Coverage with ATT&CK

The practical goal is **detection coverage** — ensuring that for each technique relevant to your environment, you have at least one detection in place.

### Step 1: Map Your Data Sources

ATT&CK v15 explicitly maps each technique to the data sources that can detect it. For cloud:

| Technique | Data Source |
|-----------|-------------|
| T1552.005 (Instance Metadata API) | Cloud Service Logs (CloudTrail) |
| T1098 (Account Manipulation) | CloudTrail: IAM events |
| T1530 (Data from Cloud Storage) | S3 Access Logs, CloudTrail data events |
| T1578 (Modify Cloud Compute) | CloudTrail: EC2 events |
| T1619 (Cloud Storage Discovery) | CloudTrail: ListBuckets API calls |

### Step 2: Score Your Coverage

For each technique in the matrix, rate your coverage: None → Partial → Good → Excellent.

Be honest. A detection that fires on every event with no tuning is worse than no detection — it creates alert fatigue and masks real signals.

### Step 3: Prioritize by Relevance and Impact

Not every ATT&CK technique applies equally to every environment. A company running exclusively serverless workloads has different exposure than one with thousands of EC2 instances.

Prioritize techniques based on:
- Your actual cloud services (EC2 vs. Lambda vs. containers)
- Your data sensitivity (what would hurt most to lose?)
- Known adversary targeting of your industry

### Step 4: Build Detections, Not Just Rules

The difference between a rule and a detection is context. A rule says "this happened." A detection says "this happened, in this context, which is abnormal given this baseline."

For example:
- **Rule**: Alert on any \`DeleteTrail\` API call
- **Detection**: Alert on any \`DeleteTrail\` API call **from an IAM user that hasn't performed admin actions in 30 days** and **from a new IP address**

The second version generates far fewer false positives and far more actionable alerts.

## How Threat Engine Maps to ATT&CK

Our platform maps every finding to one or more ATT&CK techniques. When you see a finding like "S3 bucket allows public read access," we don't just tell you it fails CIS 2.1.5. We tell you it enables:

- T1530 (Collection: Data from Cloud Storage)
- T1619 (Discovery: Cloud Storage Object Discovery)

This mapping means your CSPM findings feed directly into your security operations workflow. Your SOC team can use findings to prioritize where to focus detection engineering efforts.

---

*Understanding ATT&CK for cloud is not optional for modern security teams. The adversaries attacking your cloud infrastructure use this framework too — whether they know it by that name or not.*
    `,
  },
  {
    slug: 'cis-benchmarks-cloud-compliance-guide',
    title: 'CIS Benchmarks for Cloud: The Definitive Compliance Guide for 2026',
    excerpt: 'CIS Benchmarks remain the most trusted hardening standard in cloud security. This guide covers CIS AWS Foundations v3.0, CIS Azure v2.1, and CIS GCP v3.0 — what changed, what matters, and how to achieve compliance at scale.',
    category: 'Compliance',
    categoryColor: '#10b981',
    author: 'Anup Yadav',
    authorTitle: 'Founder & Head of Security Research',
    date: 'February 20, 2026',
    readTime: '13 min read',
    tags: ['CIS', 'Compliance', 'AWS', 'Azure', 'GCP', 'Benchmarks'],
    featured: false,
    content: `
The Center for Internet Security (CIS) Benchmarks are the gold standard for cloud security hardening. Trusted by regulators, auditors, and security teams worldwide, they provide prescriptive, consensus-based guidance for securing cloud environments.

In 2025-2026, CIS released major updates to their cloud benchmarks: AWS Foundations v3.0, Azure v2.1, and GCP v3.0. Each update reflects the evolving threat landscape and new cloud service capabilities. This guide breaks down what changed, what it means for your organization, and how to achieve compliance at scale.

## Why CIS Benchmarks Matter

Before diving into the updates, let's establish why CIS compliance matters beyond box-checking:

**1. They represent community consensus** — CIS benchmarks are developed by a global community of security professionals. When a control makes it into a CIS benchmark, it means hundreds of experienced practitioners agreed it's worth implementing.

**2. They map to regulatory requirements** — CIS benchmarks serve as a common baseline for PCI-DSS, HIPAA, NIST CSF, and SOC 2. Achieving CIS compliance creates significant overlap with these frameworks.

**3. They're measurable** — Unlike some security frameworks that describe outcomes rather than controls, CIS benchmarks are specific enough to automate. Each control either passes or fails.

## CIS AWS Foundations Benchmark v3.0: Key Changes

The AWS v3.0 release (late 2025) introduced significant restructuring and new controls.

### New in v3.0

**Networking Controls (Section 5 overhaul)**
Previous versions focused primarily on security groups. v3.0 adds:
- 5.7: Ensure that EC2 Metadata Service is set to require IMDSv2 (closes the SSRF → credential theft vector)
- 5.8: Ensure no security groups allow unrestricted egress (previously only ingress was covered)

**Identity Controls (Section 1 expansion)**
- 1.22: Ensure IAM Access Analyzer is enabled in all regions
- 1.23: Ensure that IAM Access Analyzer is configured to check all supported resource types
- 1.20: Ensure that AWS Security Hub is enabled for all regions

**Data Protection (Section 2 additions)**
- 2.4: Ensure that S3 Buckets are configured with 'Block public access' at the account level (previously only bucket-level was checked)
- 2.7: Ensure S3 bucket access logging is enabled

### What Stayed the Same (but matters more)

The foundational controls haven't changed much, but they're more important than ever:
- Root account MFA (1.5) — still violated in 18% of accounts we scan
- CloudTrail enabled for all regions (3.1) — missed in 23% of accounts
- No root account access keys (1.4) — found in 8% of accounts

### Achieving AWS CIS v3.0 Compliance

The 58 controls in AWS v3.0 fall into three categories by remediation effort:

**Automated (45 controls)** — Can be fixed via Terraform/CloudFormation with no manual steps
**Semi-automated (10 controls)** — Require human review before automated remediation
**Manual (3 controls)** — Require organizational process changes (e.g., multi-person account access policies)

## CIS Azure Benchmark v2.1: Key Changes

Azure's security model is fundamentally different from AWS, and the v2.1 benchmark reflects Microsoft's evolving security features.

### New in v2.1

**Microsoft Defender for Cloud Integration**
The benchmark now directly references Defender for Cloud as the recommended tool for implementing many controls:
- 2.1.1: Ensure that Microsoft Defender for Servers is set to 'On'
- 2.1.2: Ensure that Microsoft Defender for App Service is set to 'On'
- 2.1.13: Ensure that Microsoft Defender for Key Vault is set to 'On'

**Identity and Access (Chapter 1 overhaul)**
- 1.1.1: Ensure security defaults are enabled on Microsoft Entra ID (formerly Azure AD)
- 1.1.3: Ensure that 'Number of methods required to reset' is set to '2'
- 1.2.1: Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'

**Storage Account Security**
- 3.1: Ensure that 'Secure transfer required' is set to 'Enabled'
- 3.8: Ensure that 'Public access level' is set to Private for blob containers

## CIS GCP Benchmark v3.0: Key Changes

GCP v3.0 introduces significant coverage of Kubernetes and container services.

### GKE Security (New Section)**
The biggest change in GCP v3.0 is comprehensive Google Kubernetes Engine coverage:
- 6.2.1: Ensure Legacy Authorization is set to Disabled on Google Kubernetes Engine Clusters
- 6.3.2: Ensure Shielded GKE Nodes are Enabled
- 6.4.1: Ensure Workload Identity is Enabled for GKE Clusters
- 6.5.1: Ensure Binary Authorization is Enabled
- 6.6.5: Ensure Cluster nodes are not public

### Cloud Logging and Monitoring
- 2.1: Ensure that Cloud Audit Logging is configured properly across all services
- 2.3: Ensure that retention policies on log buckets are configured using Bucket Lock
- 2.12: Ensure that Cloud DNS logging is enabled for all VPC networks

## Implementing Multi-Cloud CIS Compliance at Scale

The challenge isn't understanding the controls — it's implementing them consistently across a complex, evolving multi-cloud environment.

### The Four Stages of CIS Compliance Maturity

**Stage 1: Visibility**
You can't fix what you can't see. Start with comprehensive scanning across all accounts and regions. Understand your current compliance posture before trying to improve it.

**Stage 2: Prioritization**
Not all CIS failures are equal. A public S3 bucket with PII is more urgent than a CloudTrail without log file validation. Prioritize by:
- Data sensitivity of affected resources
- Exploitability of the misconfiguration
- Blast radius if exploited

**Stage 3: Remediation**
Automate what you can, but be careful about automated remediation in production. Our recommended approach:
- Automated remediation for non-production environments
- Automated detection + manual approval for production

**Stage 4: Prevention**
The goal isn't to continuously fix misconfigurations — it's to prevent them from occurring. This means:
- IaC scanning in your CI/CD pipeline
- Policy-as-code (OPA/Conftest) for resource creation
- Regular developer security training

## The CIS Compliance Score

When organizations ask "what's your CIS compliance score?", the answer is almost never a single number. It varies by:

- Account/subscription (dev vs. prod)
- Region (are your resources spread across multiple regions, each with its own config?)
- Service type (your EC2 configurations might be fine, but your S3 policies aren't)

Our platform provides a multi-dimensional compliance score that breaks down compliance by account, region, service, and control category. This gives teams the granularity they need to actually improve — not just report a number.

---

*CIS compliance is a foundation, not a ceiling. Achieving it means you've addressed the most common and dangerous misconfigurations. But sophisticated attackers look for configurations that are technically compliant yet strategically exploitable. Keep building.*
    `,
  },
  {
    slug: 'zero-trust-cloud-implementation-guide',
    title: 'Zero Trust in the Cloud: From Principle to Practice in AWS and Azure',
    excerpt: 'Zero Trust is not a product — it\'s an architecture. This guide cuts through the marketing noise to show how to actually implement Zero Trust principles in your cloud environment, with concrete examples across IAM, networking, and data access.',
    category: 'Architecture',
    categoryColor: '#3b82f6',
    author: 'Anup Yadav',
    authorTitle: 'Founder & Head of Security Research',
    date: 'February 10, 2026',
    readTime: '10 min read',
    tags: ['Zero Trust', 'IAM', 'Networking', 'Architecture'],
    featured: false,
    content: `
"Zero Trust" has become one of the most overloaded terms in security. Every vendor claims their product enables it. Every framework references it. But most organizations implementing "Zero Trust" are doing little more than adding MFA to their VPN — which is not Zero Trust.

This guide is about Zero Trust as architecture — specifically, how to implement its core principles in cloud environments where traditional perimeter security never made sense in the first place.

## The Three Principles of Zero Trust

Zero Trust architecture rests on three core principles, formalized by NIST SP 800-207:

1. **Never trust, always verify** — Every request, regardless of origin, must be authenticated and authorized. Being inside the network perimeter grants no implicit trust.

2. **Use least-privilege access** — Access rights are constrained to only what is necessary for the task. Over-privileged access is a vulnerability, not a convenience.

3. **Assume breach** — Design your systems assuming that an attacker already has access to some part of your environment. Limit lateral movement and blast radius.

Notice what's absent: "install this product." Zero Trust is an architectural philosophy, not a product category.

## Why Cloud is Actually Better for Zero Trust

Here's the underappreciated truth: cloud-native environments are *more naturally aligned* with Zero Trust principles than traditional data centers.

- **Identity is the perimeter**: AWS IAM, Azure RBAC, and GCP IAM provide fine-grained, verifiable identity controls that on-prem environments rarely achieve.
- **Explicit access control**: There's no "default allow" network path in a well-configured cloud. Everything must be explicitly permitted.
- **Immutable audit trail**: CloudTrail, Activity Log, and Cloud Audit Logs provide tamper-evident records of every action.
- **Ephemeral infrastructure**: Temporary credentials, auto-scaling, containers — cloud workloads are designed to be replaced, limiting dwell time.

The challenge is that most organizations bring their on-prem assumptions to the cloud, recreating the perimeter model they were trying to escape.

## The Five Domains of Cloud Zero Trust

### 1. Identity — The New Perimeter

**Never use long-lived credentials**

AWS access keys, Azure Service Principal secrets, GCP service account key files — these are security liabilities masquerading as operational conveniences.

Instead:
- EC2/Lambda/ECS: Use IAM roles and instance metadata service (IMDSv2)
- Cross-account access: Use IAM role assumption with STS, not shared credentials
- CI/CD pipelines: Use OIDC federation to assume roles directly
- Human access: Use AWS SSO / Azure PIM / GCP Workload Identity Federation

**Apply conditional access policies**

Zero Trust identity doesn't just ask "who are you?" — it asks "who are you, from where, on what device, at what time, doing what?"

AWS: IAM Condition keys (\`aws:SourceIP\`, \`aws:RequestedRegion\`, \`aws:MultiFactorAuthPresent\`)
Azure: Conditional Access policies with risk-based authentication
GCP: VPC Service Controls + Access Context Manager

**Implement privilege just-in-time (JIT)**

Permanently elevated permissions are a standing invitation for attackers. Instead:
- AWS: Use AWS IAM Identity Center's temporary elevation
- Azure: Use Privileged Identity Management (PIM) for just-in-time admin access
- GCP: Implement time-bound access grants

### 2. Network — Micro-segmentation over VPC Perimeter

A Zero Trust network assumes the perimeter has been breached. Design accordingly.

**Replace broad security groups with specific ones**

Bad:
\`\`\`
Inbound: 0.0.0.0/0:443
Outbound: 0.0.0.0/0:*
\`\`\`

Better:
\`\`\`
Inbound: [ALB Security Group]:443
Outbound: [RDS Security Group]:5432, 443:s3.amazonaws.com
\`\`\`

**Use PrivateLink and VPC Endpoints**

Traffic between your workloads and AWS services shouldn't traverse the public internet. VPC Endpoints keep it on the AWS network — more secure and often faster.

**Implement east-west traffic controls**

North-south (in/out of VPC) controls are table stakes. The real Zero Trust gap is east-west: lateral movement between services *within* your VPC.

Use AWS Network Firewall, Azure Firewall Premium, or a service mesh (Istio/Linkerd) to inspect and control lateral traffic.

### 3. Data — Classify Before You Protect

You can't apply Zero Trust to data you haven't classified.

**Implement automatic data discovery and classification**

Modern CSPM platforms (including Threat Engine) can automatically classify data in S3, RDS, DynamoDB, and other stores. This tells you:
- What data you have
- Where it lives
- Who has access to it
- What protections are in place

**Apply purpose-limited access**

A data analyst should be able to query aggregate statistics — not read individual PII records. A payment processing service should access payment data — not audit logs. Enforce this at the IAM policy level, using resource-based policies and attribute-based access control (ABAC).

**Encrypt everywhere, manage keys yourself**

Default encryption using cloud-provider keys is better than nothing. But Zero Trust requires key management that lets you control access, rotate keys, and audit usage independently.

AWS: Use KMS Customer Managed Keys (CMK) with key policies
Azure: Use Azure Key Vault with RBAC
GCP: Use Cloud KMS with IAM conditions

### 4. Workloads — Ephemeral is Safer

Zero Trust for workloads means: assume any workload may be compromised and limit the blast radius.

**Minimize workload permissions**

Every Lambda function, ECS task, and EC2 instance should have exactly the permissions it needs — no more. Use the IAM Access Analyzer's policy generation feature to see what permissions are actually used, then tighten the policy.

**Use immutable infrastructure**

Containers and serverless functions are replaced rather than patched. This limits attacker dwell time and ensures you're running known-good images.

**Enable runtime protection**

AWS GuardDuty Runtime Monitoring, Microsoft Defender for Containers, and GCP Security Command Center can detect runtime anomalies — unusual process execution, network connections, file system access.

### 5. Visibility — You Can't Zero Trust What You Can't See

Zero Trust requires continuous verification, which requires continuous visibility.

**Centralize security logging**

All accounts, all regions, all services — feeding into a single SIEM. AWS Organizations + CloudTrail + Security Lake. Azure Monitor + Microsoft Sentinel. GCP Cloud Logging + Chronicle.

**Build behavioral baselines**

Anomaly detection requires knowing what normal looks like. Establish baselines for:
- API call patterns per IAM principal
- Data transfer volumes per service
- Inter-service communication patterns

**Implement continuous compliance validation**

Zero Trust is not a configuration state — it's a continuous process. CSPM scanning ensures that the Zero Trust controls you've put in place haven't drifted.

## The Zero Trust Maturity Model

CISA's Zero Trust Maturity Model provides a practical progression:

| Dimension | Traditional | Advanced | Optimal |
|-----------|------------|---------|---------|
| Identity | Passwords + VPN | MFA + SSO | Continuous auth + risk-based |
| Devices | Unmanaged | MDM enrolled | Attestation + posture-based access |
| Network | Implicit trust | Micro-segmented | Individual packet verification |
| Applications | VPN access | Identity-aware proxy | Least-privilege, per-session |
| Data | Perimeter protection | Tagged + encrypted | Continuous monitoring + DLP |

Most organizations we work with are in the "Advanced" tier for some dimensions and "Traditional" for others. The goal is consistent "Optimal" across all five.

---

*Zero Trust is the right architecture for cloud — not because it's trendy, but because it matches how cloud resources actually work: explicitly permissioned, API-driven, and identity-centric. Start where you have the most risk and build from there.*
    `,
  },
  {
    slug: 'iac-security-scanning-shift-left',
    title: 'IaC Security Scanning: Catching Misconfigurations Before Deployment',
    excerpt: 'Infrastructure as Code is a superpower — and a significant security risk. Learn how to integrate security scanning into your Terraform, CloudFormation, and Kubernetes pipelines to find misconfigurations before they reach production.',
    category: 'DevSecOps',
    categoryColor: '#f97316',
    author: 'Anup Yadav',
    authorTitle: 'Founder & Head of Security Research',
    date: 'January 28, 2026',
    readTime: '8 min read',
    tags: ['IaC', 'Terraform', 'DevSecOps', 'CI/CD', 'Kubernetes'],
    featured: false,
    content: `
Infrastructure as Code has fundamentally changed how organizations provision cloud resources. Terraform templates, CloudFormation stacks, Kubernetes manifests, Bicep files, Pulumi programs — your entire cloud infrastructure is now described in code that can be version-controlled, reviewed, and tested.

This creates an extraordinary opportunity for security: if your infrastructure is code, you can scan it for security issues *before it's deployed*. You can catch misconfigurations at the source, not in production.

This is the essence of "shift left" security in infrastructure — and this post shows you how to actually do it.

## The Case for IaC Security Scanning

Consider the alternative: deploy first, scan later (CSPM). You create an S3 bucket with public access in Terraform, deploy it, then your CSPM tool finds it 15 minutes later and creates a finding. You remediate, redeploy.

Now compare: your CI/CD pipeline runs Checkov on the Terraform before deployment. It fails the pipeline. You fix the template, rerun. The misconfiguration never reaches production.

The second approach is:
- **Faster** — Feedback in seconds, not minutes
- **Cheaper** — No production exposure, no incident response
- **Cleaner** — The fix lands in the source code, preventing recurrence

But CSPM and IaC scanning are not alternatives — they're complementary layers. IaC scanning catches what you write. CSPM catches what actually exists (including manual changes that bypass IaC).

## The IaC Security Landscape

The major tools for IaC security scanning:

| Tool | Languages | License | Strength |
|------|-----------|---------|---------|
| **Checkov** | 20+ (Terraform, CF, K8s, Helm...) | Apache 2.0 | Comprehensive rules, fast |
| **tfsec** | Terraform only | MIT | Deep Terraform integration |
| **KICS** | 15+ | Apache 2.0 | Good Dockerfile/compose support |
| **Terrascan** | 10+ | Apache 2.0 | OPA policy integration |
| **Semgrep** | Any (regex-based) | LGPL/SaaS | Custom rule flexibility |
| **OPA/Conftest** | Any (policy engine) | Apache 2.0 | Full policy customization |

Threat Engine's SecOps scanner integrates all major IaC formats, running 500+ rules across 14 languages with a unified findings API.

## Setting Up IaC Scanning in Your CI/CD Pipeline

### GitHub Actions Example (Terraform + Checkov)

\`\`\`yaml
name: IaC Security Scan

on:
  pull_request:
    paths: ['infrastructure/**/*.tf']

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: infrastructure/
          framework: terraform
          check: CKV_AWS_1,CKV_AWS_2   # or omit for all checks
          soft_fail: false              # fail the pipeline on findings
          output_format: sarif
          output_file_path: checkov.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov.sarif
\`\`\`

### GitLab CI Example (Kubernetes + KICS)

\`\`\`yaml
kics-scan:
  stage: security
  image: checkmarx/kics:latest
  script:
    - kics scan
        --path k8s/
        --type Kubernetes
        --fail-on HIGH,MEDIUM
        --report-formats sarif
        --output-path ./reports
  artifacts:
    reports:
      sast: reports/results.sarif
  rules:
    - changes:
        - k8s/**/*.yaml
\`\`\`

## The Top 20 IaC Findings We See

Across all the IaC repos we scan, these are the most common security issues:

### Terraform (AWS)

1. **aws_s3_bucket with public ACL** — S3 buckets created with \`acl = "public-read"\` or \`acl = "public-read-write"\`
2. **aws_security_group with unrestricted ingress** — \`cidr_blocks = ["0.0.0.0/0"]\` on sensitive ports
3. **aws_db_instance without encryption** — \`storage_encrypted = false\` on RDS instances
4. **aws_s3_bucket without versioning** — Missing \`versioning { enabled = true }\`
5. **aws_iam_policy with admin permissions** — Wildcards (\`"Action": "*"\`) in IAM policies

### Kubernetes Manifests

6. **Containers running as root** — Missing \`securityContext.runAsNonRoot: true\`
7. **Privileged containers** — \`securityContext.privileged: true\`
8. **Missing resource limits** — No \`resources.limits.cpu\` and \`resources.limits.memory\`
9. **HostPath volumes** — Mounting host filesystem into containers
10. **Default service account** — Not specifying \`serviceAccountName\`, inheriting default SA permissions

### CloudFormation

11. **AWS::RDS::DBInstance without MultiAZ** — Single point of failure
12. **AWS::CloudTrail::Trail with S3BucketName to public bucket**
13. **AWS::IAM::Role with inline policies containing wildcards**
14. **AWS::EC2::Instance with AssociatePublicIpAddress: true**
15. **Missing DeletionPolicy** — Resources that get deleted on stack deletion

## Writing Custom IaC Policies with OPA

For requirements specific to your organization, you need custom policies. Open Policy Agent (OPA) with Conftest is the most flexible approach.

### Example: Enforce Mandatory Tags

\`\`\`rego
package main

deny[msg] {
  resource := input.resource.aws_instance[_]
  not resource.config.tags.Environment
  msg := sprintf("aws_instance must have an Environment tag: %v", [resource.address])
}

deny[msg] {
  resource := input.resource.aws_instance[_]
  not resource.config.tags.Owner
  msg := sprintf("aws_instance must have an Owner tag: %v", [resource.address])
}
\`\`\`

### Example: Enforce Approved AMIs Only

\`\`\`rego
package main

approved_ami_prefixes := {"ami-0123456789", "ami-hardened-"}

deny[msg] {
  resource := input.resource.aws_instance[_]
  ami := resource.config.ami
  not any([startswith(ami, prefix) | prefix := approved_ami_prefixes[_]])
  msg := sprintf("EC2 instance uses unapproved AMI: %v. Must use approved golden AMIs.", [ami])
}
\`\`\`

## The Pipeline Security Gates

A mature IaC security pipeline has multiple gates:

**Gate 1: Pre-commit (developer machine)**
- Tool: pre-commit hooks with Checkov or tfsec
- When: Before code is committed
- Action: Warning, allows bypass with \`--no-verify\`

**Gate 2: Pull Request Check**
- Tool: Checkov, KICS, or Semgrep via CI
- When: Every PR
- Action: **Blocking** — PR cannot merge with HIGH findings

**Gate 3: Pre-deployment**
- Tool: Terraform plan + security scan of the plan
- When: Before \`terraform apply\`
- Action: **Blocking** — Deployment cannot proceed with new HIGH findings

**Gate 4: Post-deployment (CSPM)**
- Tool: CSPM platform (Threat Engine)
- When: Continuous, every 15 minutes
- Action: **Alerting** — Catches manual changes and configuration drift

## Reducing Noise: Smart Suppression

Raw IaC scanners generate a lot of false positives. Here's how to manage it:

**Baseline suppression**: On first run, accept all existing findings as your baseline. Only new findings introduced in a PR should block it.

**Contextual suppression**: Some findings are intentional. A public S3 bucket hosting a static website is fine. Suppress with inline comments:

\`\`\`hcl
resource "aws_s3_bucket" "website" {
  bucket = "my-public-website"

  # checkov:skip=CKV_AWS_20:Public access is intentional for static website
  # checkov:skip=CKV2_AWS_6:Public access configured intentionally
}
\`\`\`

**Severity thresholds**: Block on HIGH and CRITICAL, warn on MEDIUM and LOW. Don't try to achieve perfection — aim for a meaningful security bar.

---

*IaC security scanning is the highest-ROI security investment most organizations can make. The cost is low (these tools are mostly free), the integration is simple, and the impact is immediate. If you're deploying infrastructure without IaC scanning, you're deploying misconfigurations.*
    `,
  },
  {
    slug: 'ai-ml-cloud-threat-detection',
    title: 'AI-Powered Cloud Threat Detection: Signal vs. Noise in 2026',
    excerpt: 'Machine learning is transforming cloud threat detection — but only when applied correctly. We examine where AI genuinely improves detection quality, where it fails, and how to evaluate ML-based security tools without the hype.',
    category: 'AI Security',
    categoryColor: '#06b6d4',
    author: 'Anup Yadav',
    authorTitle: 'Founder & Head of Security Research',
    date: 'January 15, 2026',
    readTime: '9 min read',
    tags: ['AI', 'Machine Learning', 'Threat Detection', 'UEBA'],
    featured: false,
    content: `
Every security vendor now claims to use "AI" and "machine learning." These terms have been so thoroughly marketed that they've become meaningless. Yet the underlying technologies — when applied correctly — genuinely do improve threat detection quality in cloud environments.

This post separates the real from the theater. Where does ML actually help in cloud security? Where does it create more problems than it solves? How do you evaluate these claims without a PhD in data science?

## The Core Problem: Signal-to-Noise Ratio

Modern cloud environments generate staggering volumes of security events. A mid-sized AWS environment with 50 accounts might generate:

- 500 million CloudTrail events per day
- 2 billion VPC Flow Log records per day
- 50 million GuardDuty findings per year

No human team can review all of this. Rule-based systems (alert on these 500 specific conditions) create alert fatigue. You need something that can find the needle in a haystack — and change its definition of "needle" as attackers adapt.

This is where ML genuinely helps: not as a replacement for rules, but as a way to surface anomalies that rules miss.

## Where ML Actually Works in Cloud Security

### 1. Behavioral Baselines and Anomaly Detection

**The problem rules can't solve**: An IAM user who normally calls \`DescribeInstances\` in us-east-1 suddenly calls 200 different API endpoints across 8 regions in 3 hours. No specific call is malicious. The *pattern* is.

**What ML does**: Establish baselines for each IAM principal (user, role, service) — typical API call patterns, timing, regions, volumes. Flag deviations that exceed statistical thresholds.

**Real-world impact**: We've caught credential theft using this approach that rules-based systems missed entirely. The attacker used legitimate API calls in unusual combinations.

**Limitations**: Requires 2-4 weeks of baseline data. Generates more false positives immediately after organizational changes. High-privilege credentials with naturally variable behavior are harder to baseline.

### 2. Network Traffic Anomaly Detection

**The problem**: A container in your EKS cluster starts making DNS queries to a domain registered 3 days ago, with low reputation, at 3 AM. Individual packets are normal. The behavior isn't.

**What ML does**: Cluster normal communication patterns (which services talk to which, at what volumes, at what times). Flag connections that don't fit established patterns, using features like:
- Domain age and reputation
- Query timing relative to application patterns
- Geographic destination anomalies
- Protocol tunneling indicators (DNS over TCP, unusual packet sizes)

**Real-world impact**: ML-based network anomaly detection catches C2 beaconing and data exfiltration that signature-based tools miss.

### 3. Identity Risk Scoring

**The problem**: Not all IAM principals are equally risky. An admin account for a finance system is higher risk than a read-only monitoring role. Prioritizing security work requires scoring.

**What ML does**: Build risk scores for each identity based on:
- Permissions breadth and sensitivity
- Historical usage patterns
- Peer group comparison (is this role unusually permissive compared to similar roles?)
- Temporal patterns (unusually active at night?)
- Access to sensitive data sources

**Real-world impact**: Risk-scored identities let security teams focus remediation on the IAM entities that matter most.

### 4. Cloud Resource Relationship Graphs

**The problem**: A standalone finding (this IAM role has excessive permissions) doesn't show you the blast radius. To understand impact, you need to understand relationships.

**What graph ML does**: Build a knowledge graph of cloud resources and their relationships. Use graph algorithms (node centrality, community detection) to identify:
- "Crown jewel" resources that many other resources can reach
- "Bridge" identities that connect otherwise isolated segments
- Attack paths from low-privilege entry points to high-value targets

**Real-world impact**: Graph-based analysis reveals attack paths that individual findings miss. "This Lambda function seems harmless, but it can assume a role that has access to the production database" is only visible with graph analysis.

## Where ML Fails in Cloud Security

Being honest about limitations is essential to using these tools effectively.

### 1. Novel Attack Techniques

ML models trained on historical data can't detect truly novel techniques. If an attacker uses a technique that's never appeared in your training data, an unsupervised model may not flag it as anomalous — especially if the attack is designed to blend with legitimate activity.

**Mitigation**: Layer ML with signature-based detection for known techniques, and human threat hunting for the novel ones.

### 2. Slow, Low-Volume Attacks

ML anomaly detection thrives on behavioral patterns. An attacker who moves slowly — one API call every few hours, never exceeding baseline thresholds — can evade anomaly-based detection.

**Mitigation**: Long-horizon analysis (weeks, not hours) and statistical methods that are sensitive to low-base-rate events.

### 3. Short-Lived Environments

Many cloud workloads are ephemeral — Lambda functions live seconds, containers spin up and down. Behavioral baselines require *time* to build. Ephemeral workloads don't give you that time.

**Mitigation**: Cluster workloads by type and build baselines at the workload-type level, not the individual instance level.

### 4. Explainability

When an ML model flags something as anomalous, can it explain why? "The model thinks this is suspicious" isn't actionable for a SOC analyst. They need to understand *what specific behavior* was unusual.

**What good looks like**: "This IAM role executed 47 unique API actions in the last hour. Its 90-day baseline shows 8 unique API actions per day. The outlier actions include CreateUser, AttachRolePolicy, and AssumeRole — all high-privilege identity operations."

**What bad looks like**: "Risk score: 94/100" with no explanation.

## How to Evaluate ML-Based Security Tools

When evaluating CSPM or cloud detection tools claiming ML capabilities:

**Ask for benchmarks, not demos**
Demos are curated. Ask for detection rates on real-world attack datasets (MITRE ATT&CK Evaluations are a useful reference point).

**Test with red team scenarios**
Run specific attack scenarios in a test environment and see if the tool catches them. Don't rely on vendor-run proof of concepts.

**Measure false positive rates**
A tool that catches 100% of attacks but generates 10,000 false positives per day is worse than useless. Ask for false positive rates, not just detection rates.

**Evaluate explainability**
For every alert the tool generates, can you understand *why* it fired? Can your tier-1 analyst investigate it without a data scientist?

**Check model refresh cycles**
ML models become stale as your environment changes. How often does the vendor retrain models? Can you trigger retraining when you know a major infrastructure change is coming?

---

*ML in cloud security is not magic, but it is genuine. The best applications are narrow, well-defined problems where statistical anomaly detection has a real advantage over rules. The worst applications are "we use AI" marketing claims that describe manual rules with a machine learning wrapper. Know the difference.*
    `,
  },
  {
    slug: 'kubernetes-security-posture-management',
    title: 'Kubernetes Security Posture Management: 10 Controls That Matter Most',
    excerpt: 'Kubernetes is the most complex attack surface in modern cloud infrastructure. This guide covers the 10 most impactful security controls for EKS, AKS, and GKE — with concrete implementation steps and real-world findings data.',
    category: 'Kubernetes',
    categoryColor: '#3b82f6',
    author: 'Anup Yadav',
    authorTitle: 'Founder & Head of Security Research',
    date: 'January 5, 2026',
    readTime: '12 min read',
    tags: ['Kubernetes', 'EKS', 'AKS', 'GKE', 'Container Security'],
    featured: true,
    content: `
Kubernetes has won the container orchestration wars. EKS, AKS, GKE, and self-managed clusters now run the majority of cloud-native workloads. And with that dominance comes an enormous, complex attack surface.

A default Kubernetes cluster is not secure. The complexity that makes Kubernetes powerful — its API server, RBAC system, admission controllers, network policies, pod security — also creates numerous opportunities for misconfiguration.

This guide covers the 10 security controls that have the highest impact-to-effort ratio across the EKS, AKS, and GKE deployments we analyze.

## The Kubernetes Threat Landscape

Before the controls, context: what are attackers actually doing against Kubernetes?

Based on our analysis of Kubernetes security incidents and ATT&CK for Containers:

- **52%** of Kubernetes compromises start with exposed Kubernetes API servers or dashboards
- **31%** exploit overpermissive RBAC configurations
- **28%** use container escapes to reach the host
- **45%** result in cryptomining (the majority of commodity attacks)
- **18%** achieve lateral movement to cloud provider credentials via node IAM roles

## Control 1: Restrict API Server Access

The Kubernetes API server is the crown jewel. If an attacker can authenticate to it, they own the cluster.

**Finding rate**: 41% of EKS clusters have API server endpoints accessible from 0.0.0.0/0

**Fix (EKS)**:
\`\`\`bash
aws eks update-cluster-config \\
  --name my-cluster \\
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs="10.0.0.0/8",endpointPrivateAccess=true
\`\`\`

**Better fix**: Disable public endpoint entirely and use AWS VPN or Direct Connect for API access. Requires bastion or VPN for kubectl.

## Control 2: Enable RBAC and Remove Cluster-Admin

RBAC is enabled by default in modern Kubernetes, but it's often misconfigured — roles that are too broad, bindings to service accounts that don't need them.

**Finding rate**: 68% of clusters have at least one ClusterRoleBinding granting cluster-admin outside of system components

**Audit cluster-admin bindings**:
\`\`\`bash
kubectl get clusterrolebindings -o json | \\
  jq '.items[] | select(.roleRef.name=="cluster-admin") |
      {name: .metadata.name, subjects: .subjects}'
\`\`\`

**Principle of least privilege for service accounts**: Generate minimal RBAC policies based on observed API usage using tools like \`kubectl-who-can\` and \`rbac-tool\`.

## Control 3: Enable Pod Security Standards

Pod Security Admission (PSA), which replaced Pod Security Policy in K8s 1.25, provides three security profiles:

- **Privileged**: No restrictions (use only for system components)
- **Baseline**: Prevents known privilege escalations
- **Restricted**: Heavily restricted, follows security best practices

**Finding rate**: 73% of namespaces have no Pod Security Standard enforced

**Enable per namespace**:
\`\`\`yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.29
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
\`\`\`

## Control 4: Disable Auto-mounting of Service Account Tokens

By default, Kubernetes mounts a service account token into every pod. This token can be used to authenticate to the API server — an easy target for compromised containers.

**Finding rate**: 88% of workloads mount service account tokens unnecessarily

**Fix at the pod level**:
\`\`\`yaml
spec:
  automountServiceAccountToken: false
\`\`\`

**Fix at the service account level**:
\`\`\`yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
automountServiceAccountToken: false
\`\`\`

## Control 5: Set Resource Limits on All Containers

Missing resource limits allow a single container to consume all CPU/memory on a node — or all compute credits in a cryptomining scenario.

**Finding rate**: 61% of containers have no CPU or memory limits

**Fix**:
\`\`\`yaml
resources:
  requests:
    cpu: "250m"
    memory: "256Mi"
  limits:
    cpu: "1000m"
    memory: "512Mi"
\`\`\`

**Enforce with LimitRange**:
\`\`\`yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
spec:
  limits:
  - default:
      cpu: "500m"
      memory: "256Mi"
    defaultRequest:
      cpu: "250m"
      memory: "128Mi"
    type: Container
\`\`\`

## Control 6: Implement Network Policies

By default, all pods can communicate with all other pods across all namespaces. Network policies implement micro-segmentation at the network level.

**Finding rate**: 79% of clusters have no namespace-level network policies

**Deny-all baseline + selective allow**:
\`\`\`yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - port: 8080
\`\`\`

## Control 7: Enable Audit Logging

Kubernetes audit logs are your security audit trail. Without them, you have no record of who did what to your cluster.

**Finding rate**: 34% of self-managed and 21% of managed Kubernetes clusters have insufficient audit logging

**EKS audit logging**:
\`\`\`bash
aws eks update-cluster-config \\
  --name my-cluster \\
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
\`\`\`

## Control 8: Use Image Security Scanning and Admission Control

Every container image is a potential attack vector. Unscanned images may contain known CVEs that are trivially exploitable.

**Two-layer approach**:

1. **Scan in CI/CD** before images are pushed (Trivy, Snyk, Grype)
2. **Enforce at admission** using an admission webhook that rejects images with HIGH/CRITICAL CVEs

**EKS with Amazon ECR Enhanced Scanning**:
\`\`\`bash
aws ecr put-registry-scanning-configuration \\
  --scan-type ENHANCED \\
  --rules '[{"repositoryFilters":[{"filter":"*","filterType":"WILDCARD"}],"scanFrequency":"CONTINUOUS_SCAN"}]'
\`\`\`

## Control 9: Limit Node IAM Permissions (EKS-specific)

In EKS, node groups have IAM roles. If a container escapes to the node, it can use the node's IAM role to call AWS APIs. This is a common escalation path.

**Finding rate**: 56% of EKS node groups have IAM roles with permissions beyond EC2 baseline

**Use IRSA (IAM Roles for Service Accounts) instead of node-level permissions**:

Assign IAM permissions to specific service accounts, not to node groups. Each pod gets only the AWS permissions it needs.

\`\`\`bash
eksctl create iamserviceaccount \\
  --name my-app \\
  --namespace production \\
  --cluster my-cluster \\
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess \\
  --approve
\`\`\`

## Control 10: Enable Runtime Security

Even with all the above controls, containers can be exploited through application vulnerabilities. Runtime security provides the last line of defense.

Tools:
- **Falco** (CNCF): Rules-based runtime detection, open source
- **Amazon GuardDuty Runtime Monitoring**: EKS-native, no agent required
- **Microsoft Defender for Containers**: AKS-native
- **GCP Security Command Center**: GKE-native

**Critical Falco rules to enable**:
- Terminal shell in container
- Privilege escalation via setuid binary
- Contact cloud metadata service from container
- Outbound connection to known C2 IP ranges
- Write below binary directory

---

*Kubernetes security is an ongoing practice, not a one-time configuration. These 10 controls give you a strong foundation, but the goal is continuous improvement — measure, fix, measure again. Your CSPM platform should be continuously assessing your Kubernetes posture alongside your cloud resource configuration.*
    `,
  },
  {
    slug: 'multi-cloud-security-strategy-2026',
    title: 'Multi-Cloud Security Strategy: Managing Risk Across AWS, Azure, and GCP',
    excerpt: 'Most enterprises now use 2+ cloud providers. The security challenges of multi-cloud are real — different security models, fragmented visibility, and inconsistent controls. Here\'s how to build a coherent security strategy that works across all of them.',
    category: 'Strategy',
    categoryColor: '#10b981',
    author: 'Anup Yadav',
    authorTitle: 'Founder & Head of Security Research',
    date: 'December 20, 2025',
    readTime: '10 min read',
    tags: ['Multi-Cloud', 'AWS', 'Azure', 'GCP', 'Strategy', 'CSPM'],
    featured: false,
    content: `
Eighty-seven percent of enterprises now use multiple cloud providers. Whether by design (best-of-breed selection) or by acquisition (buying companies with existing cloud commitments), multi-cloud is the operational reality of enterprise IT.

The security implications are significant. Each cloud provider has a distinct security model, a different set of controls, different native security services, and different IAM systems. Achieving consistent security posture across all of them requires deliberate strategy.

This post covers how to build a multi-cloud security strategy that actually works.

## Why Multi-Cloud Security Is Hard

Let's be concrete about the challenges:

**Different IAM models**: AWS uses IAM with JSON policies and trust relationships. Azure uses RBAC with built-in and custom roles assigned at subscription/resource scopes. GCP uses IAM with project-level bindings and service accounts. The underlying concepts are similar; the implementations are completely different.

**Different security primitives**: AWS has Security Groups, NACLs, and VPC endpoints. Azure has NSGs, ASGs, and Private Endpoints. GCP has VPC Firewall Rules and VPC Service Controls. You can't write one security policy and apply it everywhere.

**Different logging models**: CloudTrail (AWS), Activity Log (Azure), Cloud Audit Logs (GCP) — each with different event schemas, different retention policies, different query interfaces.

**Visibility gaps**: Most organizations end up with AWS security findings in one tool, Azure findings in another, GCP in a third. No unified view of risk.

**Compliance fragmentation**: Your CIS compliance score for AWS and your Azure compliance score don't add up to a meaningful picture of your overall posture.

## The Multi-Cloud Security Architecture

A robust multi-cloud security architecture has four layers:

### Layer 1: Unified Identity

Despite different IAM models, you should strive for a single identity source of truth. Most enterprises use Azure Active Directory (Microsoft Entra ID) as their IdP, federating to AWS via IAM Identity Center and to GCP via Workforce Identity Federation.

Benefits:
- Single MFA policy applied consistently
- Centralized access reviews
- Consistent provisioning/deprovisioning
- Unified privileged access management

### Layer 2: Unified Policy

While you can't use identical policies across clouds, you can enforce equivalent controls. This requires mapping security requirements to each cloud's implementation:

| Security Requirement | AWS | Azure | GCP |
|---------------------|-----|-------|-----|
| No internet-accessible storage | S3 Block Public Access | Storage Account Public Access Disabled | Uniform Bucket-Level Access |
| Encrypt at rest | KMS CMK | Azure Key Vault Key | Cloud KMS |
| Audit all admin actions | CloudTrail | Activity Log | Cloud Audit Logs |
| Network segmentation | Security Groups + NACLs | NSGs + ASGs | VPC Firewall Rules |

### Layer 3: Unified Monitoring

Centralizing security data from all clouds into a single SIEM/SOAR is essential. Common approaches:

**Option 1: Microsoft Sentinel** — Native Azure, strong support for AWS (via connector) and GCP (via connector). Best if you're Azure-heavy.

**Option 2: Splunk Cloud** — Cloud-agnostic, strong parsing of all major cloud logs. Higher cost.

**Option 3: Elastic Security (self-managed)** — Most flexible, requires operational overhead.

Regardless of tool, ensure you're ingesting: IAM events, network flow logs, object storage access logs, and managed service logs (RDS, AKS, etc.).

### Layer 4: Unified Compliance

A multi-cloud CSPM platform (like Threat Engine) provides compliance scoring normalized across clouds. Instead of:
- "AWS CIS score: 78%"
- "Azure CIS score: 84%"
- "GCP CIS score: 71%"

You get: "Your overall cloud security posture: 78%. Here are the top 10 issues across all providers by risk impact."

This normalized view is what executives need for risk communication and what security teams need for prioritization.

## The Multi-Cloud Security Operating Model

Technology is only part of the solution. The operating model matters equally.

### Centralize Policy, Federate Execution

Security policies should be defined centrally (by a cloud security team or CISO office), then executed by cloud-specific teams who understand each provider's implementation.

Don't try to have one team own security for AWS, Azure, and GCP. The specialization required is too deep. Instead, have a central team own requirements and measurement, and distributed teams own implementation.

### Build a Cloud Security Baseline

Define the minimum security bar for every cloud account, regardless of provider:

1. MFA required for all human access
2. No long-lived credentials
3. Encryption at rest enabled for all storage
4. Audit logging enabled and retained for 90+ days
5. No public-facing resources without explicit business justification
6. Secrets stored in cloud-native secrets management (not environment variables)

This baseline should be automatically enforced at account creation and continuously validated.

### Implement a Cloud Security Exception Process

Not every security control can be universally applied. Some workloads have legitimate requirements for configurations that would otherwise be flagged.

Build a formal exception process:
1. Business justification required
2. Compensating controls documented
3. Time-limited exceptions (not permanent)
4. Reviewed quarterly
5. Tracked in your CSPM platform as acknowledged risks

---

*Multi-cloud security is more manageable than it looks, but it requires intentional architecture. The organizations that struggle with it are trying to apply single-cloud thinking to a multi-cloud environment. The ones that succeed treat multi-cloud security as its own discipline — with a unified policy layer, federated execution, and centralized visibility.*
    `,
  },
];

export function getPostBySlug(slug) {
  return posts.find(p => p.slug === slug) || null;
}

export function getFeaturedPosts() {
  return posts.filter(p => p.featured);
}

export function getRecentPosts(count = 3) {
  return posts.slice(0, count);
}

export function getPostsByCategory(category) {
  return posts.filter(p => p.category === category);
}

export const categories = [...new Set(posts.map(p => p.category))];
