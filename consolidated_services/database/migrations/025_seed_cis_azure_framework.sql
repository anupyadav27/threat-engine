-- Migration 025: Seed CIS Azure Foundations Benchmark 1.5.0 + Azure Security Benchmark 3.0
-- Tables: compliance_frameworks, compliance_controls
-- Safe to re-run (ON CONFLICT DO UPDATE / ON CONFLICT DO NOTHING).

-- ============================================================================
-- FRAMEWORKS
-- ============================================================================

INSERT INTO compliance_frameworks (
    framework_id, framework_name, version, description, authority, category,
    is_active, framework_data
) VALUES
(
    'cis_azure_1_5',
    'CIS Microsoft Azure Foundations Benchmark',
    '1.5.0',
    'Security configuration best practices for Microsoft Azure cloud environments, covering identity, storage, database, logging, networking, virtual machines, app services, and key vault.',
    'Center for Internet Security (CIS)',
    'cloud_security',
    TRUE,
    '{"provider": "azure", "total_controls": 87, "sections": 9, "url": "https://www.cisecurity.org/benchmark/azure"}'::jsonb
),
(
    'azure_security_benchmark',
    'Microsoft Azure Security Benchmark',
    '3.0',
    'Microsoft recommended security best practices for Azure workloads, covering network security, identity management, privileged access, data protection, asset management, logging, incident response, posture, and DevOps security.',
    'Microsoft',
    'cloud_security',
    TRUE,
    '{"provider": "azure", "total_controls": 82, "url": "https://learn.microsoft.com/en-us/security/benchmark/azure/"}'::jsonb
)
ON CONFLICT (framework_id) DO UPDATE SET
    framework_name = EXCLUDED.framework_name,
    version        = EXCLUDED.version,
    description    = EXCLUDED.description,
    is_active      = TRUE,
    updated_at     = NOW();

-- ============================================================================
-- CIS AZURE 1.5 CONTROLS
-- ============================================================================
-- control_id format: cis_azure_1_5_<section>_<number>

INSERT INTO compliance_controls (
    control_id, framework_id, control_number, control_name, control_description,
    control_type, severity, control_family, is_active
) VALUES

-- ── Section 1: Identity and Access Management (1.1–1.25) ──────────────────────
('cis_azure_1_5_1_1',  'cis_azure_1_5', '1.1',  'Ensure Security Defaults are enabled on Azure Active Directory', 'Microsoft provides security defaults to help organizations remain secure by default. Security defaults contain preconfigured security settings for common attacks.', 'preventive', 'critical', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_2',  'cis_azure_1_5', '1.2',  'Ensure that ''Multi-Factor Auth Status'' is ''Enabled'' for all Privileged Users', 'Enable multi-factor authentication for all users who have write access to Azure resources.', 'preventive', 'critical', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_3',  'cis_azure_1_5', '1.3',  'Ensure that ''Multi-Factor Auth Status'' is ''Enabled'' for all Non-Privileged Users', 'Enable multi-factor authentication for all non-privileged users.', 'preventive', 'high', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_4',  'cis_azure_1_5', '1.4',  'Ensure that ''Allow users to remember multi-factor authentication on devices they trust'' is Disabled', 'Do not allow users to remember MFA on devices.', 'preventive', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_5',  'cis_azure_1_5', '1.5',  'Ensure that ''Number of days before users are asked to re-confirm their authentication information'' is not set to ''0''', 'Require re-authentication periodically.', 'preventive', 'low', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_6',  'cis_azure_1_5', '1.6',  'Ensure that ''Number of methods required to reset'' is set to ''2''', 'Require two authentication methods to reset a password.', 'preventive', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_7',  'cis_azure_1_5', '1.7',  'Ensure that a Custom Bad Password List is set to ''Enforce'' on Azure Active Directory', 'Use a custom banned password list.', 'preventive', 'low', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_8',  'cis_azure_1_5', '1.8',  'Ensure that ''Notify users on password resets?'' is set to ''Yes''', 'Notify users when their password is reset.', 'detective', 'low', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_9',  'cis_azure_1_5', '1.9',  'Ensure that ''Notify all admins when other admins reset their password?'' is set to ''Yes''', 'Notify admins when another admin resets their password.', 'detective', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_10', 'cis_azure_1_5', '1.10', 'Ensure that ''Users can consent to apps accessing company data on their behalf'' is set to ''No''', 'Disallow user consent for OAuth apps.', 'preventive', 'high', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_11', 'cis_azure_1_5', '1.11', 'Ensure that ''Users can add gallery apps to their Access Panel'' is set to ''No''', 'Restrict users from adding gallery apps.', 'preventive', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_12', 'cis_azure_1_5', '1.12', 'Ensure that ''Users can register applications'' is set to ''No''', 'Restrict application registration to admins.', 'preventive', 'high', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_13', 'cis_azure_1_5', '1.13', 'Ensure that ''Guest users permissions are limited'' is set to ''Yes''', 'Limit permissions for guest users.', 'preventive', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_14', 'cis_azure_1_5', '1.14', 'Ensure that ''Members can invite'' is set to ''No''', 'Only admins can invite external users.', 'preventive', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_15', 'cis_azure_1_5', '1.15', 'Ensure that ''Guests can invite'' is set to ''No''', 'Guests cannot invite other guests.', 'preventive', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_16', 'cis_azure_1_5', '1.16', 'Ensure that ''Restrict access to Azure AD administration portal'' is set to ''Yes''', 'Non-admins cannot access Azure AD portal.', 'preventive', 'high', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_17', 'cis_azure_1_5', '1.17', 'Ensure that no custom subscription owner roles are created', 'Avoid creating custom roles with owner-level permissions.', 'preventive', 'high', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_18', 'cis_azure_1_5', '1.18', 'Ensure that ''Subscription owners'' have fewer than 3 persons', 'Minimize subscription owners to reduce blast radius.', 'preventive', 'high', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_19', 'cis_azure_1_5', '1.19', 'Ensure that ''Service Principals'' have expiring credentials', 'Service principals should use credentials with expiry dates.', 'preventive', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_20', 'cis_azure_1_5', '1.20', 'Ensure that ''Service Principals'' are not ''Owner'' or ''Contributor'' at subscription scope', 'Restrict overprivileged service principals.', 'preventive', 'critical', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_21', 'cis_azure_1_5', '1.21', 'Ensure that ''Managed Identity'' is used for Azure service authentication', 'Use managed identities instead of credentials where possible.', 'preventive', 'medium', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_22', 'cis_azure_1_5', '1.22', 'Ensure that no legacy authentication protocols are allowed', 'Block basic auth and other legacy protocols.', 'preventive', 'high', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_23', 'cis_azure_1_5', '1.23', 'Ensure that ''Privileged Identity Management'' is enabled for roles with high privilege', 'Use PIM for just-in-time access to privileged roles.', 'preventive', 'high', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_24', 'cis_azure_1_5', '1.24', 'Ensure that user ''Object ID'' is used for identifying the account performing actions', 'Track actions by object ID not display name.', 'detective', 'low', 'Identity and Access Management', TRUE),
('cis_azure_1_5_1_25', 'cis_azure_1_5', '1.25', 'Ensure that no users have Global Administrator role permanently', 'Global admin should be time-bound via PIM.', 'preventive', 'critical', 'Identity and Access Management', TRUE),

-- ── Section 2: Microsoft Defender for Cloud (2.1–2.15) ────────────────────────
('cis_azure_1_5_2_1',  'cis_azure_1_5', '2.1',  'Ensure that Microsoft Defender for Servers is set to ''On''', 'Enable Defender for Servers to detect threats on VMs.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_2',  'cis_azure_1_5', '2.2',  'Ensure that Microsoft Defender for App Service is set to ''On''', 'Enable Defender for App Service.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_3',  'cis_azure_1_5', '2.3',  'Ensure that Microsoft Defender for Azure SQL Database Servers is set to ''On''', 'Enable Defender for Azure SQL.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_4',  'cis_azure_1_5', '2.4',  'Ensure that Microsoft Defender for SQL Servers on Machines is set to ''On''', 'Enable Defender for SQL on VMs.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_5',  'cis_azure_1_5', '2.5',  'Ensure that Microsoft Defender for Open-Source Relational Databases is set to ''On''', 'Enable Defender for open-source databases.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_6',  'cis_azure_1_5', '2.6',  'Ensure that Microsoft Defender for Storage is set to ''On''', 'Enable Defender for Storage.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_7',  'cis_azure_1_5', '2.7',  'Ensure that Microsoft Defender for Containers is set to ''On''', 'Enable Defender for Containers.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_8',  'cis_azure_1_5', '2.8',  'Ensure that Microsoft Defender for Azure Cosmos DB is set to ''On''', 'Enable Defender for Cosmos DB.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_9',  'cis_azure_1_5', '2.9',  'Ensure that Microsoft Defender for Key Vault is set to ''On''', 'Enable Defender for Key Vault.', 'detective', 'high', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_10', 'cis_azure_1_5', '2.10', 'Ensure that Microsoft Defender for DNS is set to ''On''', 'Enable Defender for DNS.', 'detective', 'medium', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_11', 'cis_azure_1_5', '2.11', 'Ensure that Microsoft Defender for Resource Manager is set to ''On''', 'Enable Defender for Resource Manager.', 'detective', 'medium', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_12', 'cis_azure_1_5', '2.12', 'Ensure that Microsoft Cloud Security Benchmark policies are not set to ''Disabled''', 'Keep MCSB policy initiatives enabled.', 'preventive', 'medium', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_13', 'cis_azure_1_5', '2.13', 'Ensure that ''Auto provisioning of Log Analytics agent for Azure VMs'' is set to ''On''', 'Auto-provision monitoring agents.', 'preventive', 'medium', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_14', 'cis_azure_1_5', '2.14', 'Ensure any of the ASC Default policy setting is not set to ''Disabled''', 'Keep default ASC security policies enabled.', 'preventive', 'medium', 'Microsoft Defender for Cloud', TRUE),
('cis_azure_1_5_2_15', 'cis_azure_1_5', '2.15', 'Ensure that ''Security contact emails'' is set', 'Set a security contact email for alerts.', 'preventive', 'low', 'Microsoft Defender for Cloud', TRUE),

-- ── Section 3: Storage Accounts (3.1–3.15) ────────────────────────────────────
('cis_azure_1_5_3_1',  'cis_azure_1_5', '3.1',  'Ensure that ''Secure transfer required'' is set to ''Enabled''', 'Force HTTPS for storage account connections.', 'preventive', 'high', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_2',  'cis_azure_1_5', '3.2',  'Ensure that storage account access keys are periodically regenerated', 'Rotate storage account access keys regularly.', 'preventive', 'medium', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_3',  'cis_azure_1_5', '3.3',  'Ensure Storage logging is enabled for Queue service for read, write, and delete requests', 'Enable storage queue logging.', 'detective', 'medium', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_4',  'cis_azure_1_5', '3.4',  'Ensure that shared access signature tokens expire within an hour', 'SAS tokens must expire within 1 hour.', 'preventive', 'medium', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_5',  'cis_azure_1_5', '3.5',  'Ensure that ''Public access level'' is set to Private for blob containers', 'Disable public blob access.', 'preventive', 'critical', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_6',  'cis_azure_1_5', '3.6',  'Ensure default action is set to ''Deny'' in Storage Account Network Access', 'Deny public network access by default.', 'preventive', 'high', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_7',  'cis_azure_1_5', '3.7',  'Ensure that ''Trusted Microsoft Services'' is enabled for Storage Account access', 'Allow trusted Azure services to bypass storage firewall.', 'preventive', 'low', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_8',  'cis_azure_1_5', '3.8',  'Ensure Soft Delete is Enabled for Azure Containers and Blob Storage', 'Enable soft delete to recover accidentally deleted blobs.', 'preventive', 'medium', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_9',  'cis_azure_1_5', '3.9',  'Ensure storage for critical data are encrypted with Customer Managed Keys', 'Use CMK for sensitive storage accounts.', 'preventive', 'medium', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_10', 'cis_azure_1_5', '3.10', 'Ensure Storage logging is enabled for Blob service for read, write, and delete requests', 'Enable storage blob logging.', 'detective', 'medium', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_11', 'cis_azure_1_5', '3.11', 'Ensure Storage logging is enabled for Table service for read, write, and delete requests', 'Enable storage table logging.', 'detective', 'low', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_12', 'cis_azure_1_5', '3.12', 'Ensure that the minimum TLS version for storage accounts is set to Version 1.2', 'Require TLS 1.2 or higher for storage.', 'preventive', 'high', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_13', 'cis_azure_1_5', '3.13', 'Ensure ''Allow Azure services on the trusted services list to access this storage account'' is Enabled', 'Allow trusted Azure services.', 'preventive', 'low', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_14', 'cis_azure_1_5', '3.14', 'Ensure that ''Enable Infrastructure Encryption'' for Each Storage Account in Azure Storage is Set to enabled', 'Enable double encryption at infrastructure level.', 'preventive', 'medium', 'Storage Accounts', TRUE),
('cis_azure_1_5_3_15', 'cis_azure_1_5', '3.15', 'Ensure that Azure Files shares use SMB 3.x', 'Use SMB 3.x for Azure Files shares.', 'preventive', 'medium', 'Storage Accounts', TRUE),

-- ── Section 4: Database Services (4.1–4.9) ────────────────────────────────────
('cis_azure_1_5_4_1',  'cis_azure_1_5', '4.1',  'Ensure that ''Auditing'' is set to ''On'' for the server', 'Enable auditing for Azure SQL servers.', 'detective', 'high', 'Database Services', TRUE),
('cis_azure_1_5_4_2',  'cis_azure_1_5', '4.2',  'Ensure that ''Data encryption'' is set to ''On'' on a SQL Database', 'Enable Transparent Data Encryption.', 'preventive', 'critical', 'Database Services', TRUE),
('cis_azure_1_5_4_3',  'cis_azure_1_5', '4.3',  'Ensure that ''Threat Detection types'' is set to ''All''', 'Enable all threat detection types.', 'detective', 'high', 'Database Services', TRUE),
('cis_azure_1_5_4_4',  'cis_azure_1_5', '4.4',  'Ensure that ''Send alerts to'' is set', 'Configure threat alert recipients.', 'detective', 'medium', 'Database Services', TRUE),
('cis_azure_1_5_4_5',  'cis_azure_1_5', '4.5',  'Ensure that ''Email service and co-administrators'' is enabled', 'Notify service admins of threats.', 'detective', 'medium', 'Database Services', TRUE),
('cis_azure_1_5_4_6',  'cis_azure_1_5', '4.6',  'Ensure that ''Auditing'' Retention is ''greater than 90 days''', 'Retain audit logs for 90+ days.', 'detective', 'medium', 'Database Services', TRUE),
('cis_azure_1_5_4_7',  'cis_azure_1_5', '4.7',  'Ensure that ''Azure Active Directory Admin'' is configured', 'Set AAD admin for SQL servers.', 'preventive', 'high', 'Database Services', TRUE),
('cis_azure_1_5_4_8',  'cis_azure_1_5', '4.8',  'Ensure that Azure SQL server disables public network access', 'Disable public network access to SQL.', 'preventive', 'critical', 'Database Services', TRUE),
('cis_azure_1_5_4_9',  'cis_azure_1_5', '4.9',  'Ensure that ''Minimum TLS version'' for MySQL flexible server is set to ''TLS1.2''', 'Require TLS 1.2 for MySQL.', 'preventive', 'high', 'Database Services', TRUE),

-- ── Section 5: Logging and Monitoring (5.1–5.6) ───────────────────────────────
('cis_azure_1_5_5_1',  'cis_azure_1_5', '5.1',  'Ensure that a Diagnostic Setting exists for Subscription Activity Logs', 'Configure diagnostic settings for activity logs.', 'detective', 'high', 'Logging and Monitoring', TRUE),
('cis_azure_1_5_5_2',  'cis_azure_1_5', '5.2',  'Ensure Diagnostic Setting captures appropriate categories', 'Capture Administrative, Security, Alert, Policy categories.', 'detective', 'high', 'Logging and Monitoring', TRUE),
('cis_azure_1_5_5_3',  'cis_azure_1_5', '5.3',  'Ensure the storage container storing the activity logs is not publicly accessible', 'Lock down log storage containers.', 'preventive', 'high', 'Logging and Monitoring', TRUE),
('cis_azure_1_5_5_4',  'cis_azure_1_5', '5.4',  'Ensure the storage account containing the container with activity logs is encrypted with BYOK', 'Encrypt log storage with customer-managed keys.', 'preventive', 'medium', 'Logging and Monitoring', TRUE),
('cis_azure_1_5_5_5',  'cis_azure_1_5', '5.5',  'Ensure that logging for Azure Key Vault is ''Enabled''', 'Enable diagnostic logging for Key Vault.', 'detective', 'high', 'Logging and Monitoring', TRUE),
('cis_azure_1_5_5_6',  'cis_azure_1_5', '5.6',  'Ensure that Activity Retention Log is set to 1 year or greater', 'Retain activity logs for at least 1 year.', 'detective', 'medium', 'Logging and Monitoring', TRUE),

-- ── Section 6: Networking (6.1–6.6) ──────────────────────────────────────────
('cis_azure_1_5_6_1',  'cis_azure_1_5', '6.1',  'Ensure that RDP access from the Internet is evaluated and restricted', 'Restrict RDP (3389) from internet in NSGs.', 'preventive', 'critical', 'Networking', TRUE),
('cis_azure_1_5_6_2',  'cis_azure_1_5', '6.2',  'Ensure that SSH access from the Internet is evaluated and restricted', 'Restrict SSH (22) from internet in NSGs.', 'preventive', 'critical', 'Networking', TRUE),
('cis_azure_1_5_6_3',  'cis_azure_1_5', '6.3',  'Ensure that UDP access from the Internet is evaluated and restricted', 'Restrict UDP ports from internet in NSGs.', 'preventive', 'high', 'Networking', TRUE),
('cis_azure_1_5_6_4',  'cis_azure_1_5', '6.4',  'Ensure that HTTP(S) access from the Internet is evaluated and restricted', 'Restrict HTTP/HTTPS from internet unless intentional.', 'preventive', 'medium', 'Networking', TRUE),
('cis_azure_1_5_6_5',  'cis_azure_1_5', '6.5',  'Ensure that Network Security Group Flow Log retention period is ''greater than 90 days''', 'Retain NSG flow logs for 90+ days.', 'detective', 'medium', 'Networking', TRUE),
('cis_azure_1_5_6_6',  'cis_azure_1_5', '6.6',  'Ensure that Network Watcher is ''Enabled''', 'Enable Network Watcher in all regions.', 'detective', 'medium', 'Networking', TRUE),

-- ── Section 7: Virtual Machines (7.1–7.7) ─────────────────────────────────────
('cis_azure_1_5_7_1',  'cis_azure_1_5', '7.1',  'Ensure Virtual Machines are utilizing Managed Disks', 'Use managed disks for VMs.', 'preventive', 'medium', 'Virtual Machines', TRUE),
('cis_azure_1_5_7_2',  'cis_azure_1_5', '7.2',  'Ensure that ''OS and Data'' disks are encrypted with Customer Managed Key (CMK)', 'Use CMK for OS and data disk encryption.', 'preventive', 'high', 'Virtual Machines', TRUE),
('cis_azure_1_5_7_3',  'cis_azure_1_5', '7.3',  'Ensure that ''Unattached disks'' are encrypted with ''Customer Managed Key'' (CMK)', 'Encrypt unattached disks with CMK.', 'preventive', 'medium', 'Virtual Machines', TRUE),
('cis_azure_1_5_7_4',  'cis_azure_1_5', '7.4',  'Ensure that only approved extensions are installed', 'Audit and control installed VM extensions.', 'preventive', 'medium', 'Virtual Machines', TRUE),
('cis_azure_1_5_7_5',  'cis_azure_1_5', '7.5',  'Ensure that the latest OS Patches for all Virtual Machines are applied', 'Apply OS patches to VMs.', 'preventive', 'high', 'Virtual Machines', TRUE),
('cis_azure_1_5_7_6',  'cis_azure_1_5', '7.6',  'Ensure that the endpoint protection for all Virtual Machines is installed', 'Install endpoint protection on VMs.', 'preventive', 'high', 'Virtual Machines', TRUE),
('cis_azure_1_5_7_7',  'cis_azure_1_5', '7.7',  'Ensure that VHDs are encrypted', 'Encrypt VHDs for VMs not using managed disks.', 'preventive', 'high', 'Virtual Machines', TRUE),

-- ── Section 8: App Service (8.1–8.8) ──────────────────────────────────────────
('cis_azure_1_5_8_1',  'cis_azure_1_5', '8.1',  'Ensure App Service Authentication is set up for apps in Azure App Service', 'Enable authentication/authorization for App Service.', 'preventive', 'high', 'App Service', TRUE),
('cis_azure_1_5_8_2',  'cis_azure_1_5', '8.2',  'Ensure that ''HTTP Version'' is the latest if used to run the web app', 'Use latest HTTP version.', 'preventive', 'low', 'App Service', TRUE),
('cis_azure_1_5_8_3',  'cis_azure_1_5', '8.3',  'Ensure Web App is using the latest version of TLS encryption', 'Use TLS 1.2 or higher.', 'preventive', 'high', 'App Service', TRUE),
('cis_azure_1_5_8_4',  'cis_azure_1_5', '8.4',  'Ensure the web app has ''Client Certificates (Incoming client certificates)'' set to ''On''', 'Require client certificates for web apps.', 'preventive', 'medium', 'App Service', TRUE),
('cis_azure_1_5_8_5',  'cis_azure_1_5', '8.5',  'Ensure that Register with Azure Active Directory is enabled on App Service', 'Use managed identity for App Service.', 'preventive', 'medium', 'App Service', TRUE),
('cis_azure_1_5_8_6',  'cis_azure_1_5', '8.6',  'Ensure that ''PHP version'' is the latest, if used to run the Web app', 'Use latest PHP version.', 'preventive', 'medium', 'App Service', TRUE),
('cis_azure_1_5_8_7',  'cis_azure_1_5', '8.7',  'Ensure that ''Python version'' is the latest stable version, if used to run the Web app', 'Use latest Python version.', 'preventive', 'medium', 'App Service', TRUE),
('cis_azure_1_5_8_8',  'cis_azure_1_5', '8.8',  'Ensure that ''Java version'' is the latest, if used to run the Web app', 'Use latest Java version.', 'preventive', 'medium', 'App Service', TRUE),

-- ── Section 9: Key Vault (9.1–9.4) ────────────────────────────────────────────
('cis_azure_1_5_9_1',  'cis_azure_1_5', '9.1',  'Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults', 'Set expiry dates on Key Vault keys.', 'preventive', 'high', 'Key Vault', TRUE),
('cis_azure_1_5_9_2',  'cis_azure_1_5', '9.2',  'Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults', 'Set expiry dates on Key Vault secrets.', 'preventive', 'high', 'Key Vault', TRUE),
('cis_azure_1_5_9_3',  'cis_azure_1_5', '9.3',  'Ensure that ''Soft Delete'' is Enabled for Azure Key Vault', 'Enable soft delete on Key Vaults.', 'preventive', 'high', 'Key Vault', TRUE),
('cis_azure_1_5_9_4',  'cis_azure_1_5', '9.4',  'Ensure that ''Purge protection'' is Enabled for Azure Key Vault', 'Enable purge protection on Key Vaults.', 'preventive', 'high', 'Key Vault', TRUE)

ON CONFLICT (control_id) DO NOTHING;
