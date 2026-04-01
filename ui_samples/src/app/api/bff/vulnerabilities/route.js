/**
 * Next.js BFF interceptor for the Vulnerabilities page.
 *
 * Tries the live vulnerability engine endpoints, falls back to rich
 * deterministic mock data when the engine is unavailable or returns empty data.
 *
 * Real endpoints (vulnerability engine, port 8004):
 *   GET /api/v1/reports/dashboard
 *   GET /api/v1/reports/executive
 *   GET /api/v1/vulnerabilities/?limit=200
 *   GET /api/v1/vulnerabilities/stats/severity
 *   GET /api/v1/vulnerabilities/stats/trending
 *   GET /api/v1/agents/
 *   GET /api/v1/scans/stats/summary
 */

import { NextResponse } from 'next/server';

const NLB_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL ||
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';

// ── helpers ──────────────────────────────────────────────────────────────────
async function tryFetch(url) {
  try {
    const r = await fetch(url, { headers: { Accept: 'application/json' }, next: { revalidate: 30 } });
    if (r.ok) return r.json();
  } catch (_) {}
  return null;
}

function isDegenerate(data) {
  if (!data || typeof data !== 'object') return true;
  const vulns = data.vulnerabilities;
  if (!Array.isArray(vulns) || vulns.length === 0) return true;
  return false;
}

// ── MOCK DATA ─────────────────────────────────────────────────────────────────
// Pre-computed deterministic data covering all 6 dashboard tabs.

const AGENTS = [
  { agent_id: 'agt-prod-001',     hostname: 'prod-web-01',      platform: 'linux',   architecture: 'x86_64', status: 'active',   last_seen: -2  },
  { agent_id: 'agt-prod-002',     hostname: 'prod-api-01',      platform: 'linux',   architecture: 'x86_64', status: 'active',   last_seen: -1  },
  { agent_id: 'agt-prod-003',     hostname: 'prod-db-01',       platform: 'linux',   architecture: 'x86_64', status: 'active',   last_seen: -3  },
  { agent_id: 'agt-staging-001',  hostname: 'staging-app-01',   platform: 'linux',   architecture: 'x86_64', status: 'active',   last_seen: -5  },
  { agent_id: 'agt-dev-001',      hostname: 'dev-workstation-01',platform: 'linux',  architecture: 'arm64',  status: 'active',   last_seen: -8  },
  { agent_id: 'agt-win-001',      hostname: 'corp-win-01',      platform: 'windows', architecture: 'x86_64', status: 'active',   last_seen: -4  },
  { agent_id: 'agt-win-002',      hostname: 'corp-win-02',      platform: 'windows', architecture: 'x86_64', status: 'inactive', last_seen: -14 },
  { agent_id: 'agt-k8s-001',      hostname: 'k8s-node-01',      platform: 'linux',   architecture: 'x86_64', status: 'active',   last_seen: -1  },
  { agent_id: 'agt-k8s-002',      hostname: 'k8s-node-02',      platform: 'linux',   architecture: 'x86_64', status: 'active',   last_seen: -2  },
  { agent_id: 'agt-mac-001',      hostname: 'dev-macbook-01',   platform: 'macos',   architecture: 'arm64',  status: 'active',   last_seen: -6  },
];

const CVE_DATA = [
  { cve_id:'CVE-2024-3094', pkg:'xz-utils',          ver:'5.6.0',  cvss:10.0, sev:'CRITICAL', days:8,  agents:['agt-prod-001','agt-prod-002','agt-k8s-001'],          cwe:'CWE-506', desc:'Backdoor in XZ Utils liblzma library affecting systemd-linked distros.',                     exploit:true,  patch:true,  epss:0.97 },
  { cve_id:'CVE-2024-6387', pkg:'openssh',            ver:'9.7p1',  cvss:8.1,  sev:'CRITICAL', days:12, agents:['agt-prod-001','agt-prod-002','agt-prod-003','agt-k8s-001','agt-k8s-002'], cwe:'CWE-364', desc:'Race condition in OpenSSH server (sshd) — remote unauthenticated code execution.',       exploit:true,  patch:true,  epss:0.91 },
  { cve_id:'CVE-2023-4911', pkg:'glibc',              ver:'2.35',   cvss:7.8,  sev:'CRITICAL', days:45, agents:['agt-prod-001','agt-prod-002','agt-prod-003'],          cwe:'CWE-122', desc:'Heap-based buffer overflow in GNU C Library via GLIBC_TUNABLES environment variable.',     exploit:true,  patch:true,  epss:0.86 },
  { cve_id:'CVE-2024-21626',pkg:'runc',               ver:'1.1.11', cvss:8.6,  sev:'CRITICAL', days:22, agents:['agt-k8s-001','agt-k8s-002'],                          cwe:'CWE-22',  desc:'Container breakout via file descriptor leak in runc.',                                       exploit:true,  patch:true,  epss:0.84 },
  { cve_id:'CVE-2023-44487', pkg:'nghttp2',           ver:'1.57.0', cvss:7.5,  sev:'CRITICAL', days:90, agents:['agt-prod-001','agt-prod-002','agt-staging-001'],       cwe:'CWE-400', desc:'HTTP/2 Rapid Reset Attack causing denial of service (Rapid Reset DDoS).',                   exploit:true,  patch:true,  epss:0.82 },
  { cve_id:'CVE-2024-1086',  pkg:'linux-kernel',      ver:'6.6.14', cvss:7.8,  sev:'CRITICAL', days:18, agents:['agt-prod-001','agt-prod-003','agt-k8s-001'],          cwe:'CWE-416', desc:'Use-after-free in netfilter nf_tables allows local privilege escalation.',                  exploit:true,  patch:true,  epss:0.79 },
  { cve_id:'CVE-2024-27198', pkg:'teamcity-agent',    ver:'2023.11',cvss:9.8,  sev:'CRITICAL', days:5,  agents:['agt-dev-001'],                                        cwe:'CWE-288', desc:'Authentication bypass in JetBrains TeamCity build server.',                                  exploit:true,  patch:true,  epss:0.96 },
  { cve_id:'CVE-2023-46604', pkg:'activemq',          ver:'5.15.16',cvss:10.0, sev:'CRITICAL', days:62, agents:['agt-prod-003'],                                       cwe:'CWE-502', desc:'Remote code execution in Apache ActiveMQ via ClassInfo deserialization.',                   exploit:true,  patch:true,  epss:0.95 },
  { cve_id:'CVE-2024-4577',  pkg:'php',               ver:'8.1.28', cvss:9.8,  sev:'CRITICAL', days:9,  agents:['agt-prod-001','agt-staging-001'],                     cwe:'CWE-88',  desc:'Argument injection in PHP CGI on Windows allowing remote code execution.',                 exploit:true,  patch:true,  epss:0.88 },
  { cve_id:'CVE-2023-38408', pkg:'openssh',           ver:'9.2p1',  cvss:9.8,  sev:'CRITICAL', days:71, agents:['agt-prod-002','agt-prod-003'],                        cwe:'CWE-94',  desc:'Remote code execution in OpenSSH forwarded ssh-agent.',                                     exploit:true,  patch:true,  epss:0.83 },
  { cve_id:'CVE-2024-23897', pkg:'jenkins',           ver:'2.441',  cvss:9.8,  sev:'CRITICAL', days:14, agents:['agt-staging-001'],                                    cwe:'CWE-88',  desc:'Arbitrary file read vulnerability in Jenkins CLI could lead to RCE.',                       exploit:true,  patch:true,  epss:0.90 },
  { cve_id:'CVE-2024-22024', pkg:'ivanti-connect',    ver:'22.6',   cvss:8.3,  sev:'CRITICAL', days:20, agents:['agt-win-001'],                                        cwe:'CWE-611', desc:'XXE vulnerability in Ivanti Connect Secure allows authentication bypass.',                  exploit:true,  patch:true,  epss:0.87 },
  { cve_id:'CVE-2024-0204',  pkg:'fortra-goanywhere', ver:'7.1.1',  cvss:9.8,  sev:'CRITICAL', days:28, agents:['agt-prod-003'],                                       cwe:'CWE-425', desc:'Authentication bypass in Fortra GoAnywhere MFT admin panel.',                              exploit:true,  patch:true,  epss:0.89 },
  { cve_id:'CVE-2024-30078', pkg:'windows-wifi',      ver:'10.0',   cvss:8.8,  sev:'HIGH',     days:7,  agents:['agt-win-001','agt-win-002'],                          cwe:'CWE-787', desc:'Windows WiFi Driver Remote Code Execution Vulnerability.',                                   exploit:false, patch:true,  epss:0.71 },
  { cve_id:'CVE-2024-26169', pkg:'windows-kernel',    ver:'10.0',   cvss:7.8,  sev:'HIGH',     days:7,  agents:['agt-win-001'],                                        cwe:'CWE-269', desc:'Windows Error Reporting Service elevation of privilege.',                                     exploit:true,  patch:true,  epss:0.68 },
  { cve_id:'CVE-2024-21413', pkg:'outlook',           ver:'16.0',   cvss:9.8,  sev:'CRITICAL', days:52, agents:['agt-win-001','agt-win-002'],                          cwe:'CWE-20',  desc:'Microsoft Outlook HYPERLINK bypass allows credential leakage / RCE.',                       exploit:true,  patch:true,  epss:0.92 },
  { cve_id:'CVE-2024-34102', pkg:'magento',           ver:'2.4.6',  cvss:9.8,  sev:'CRITICAL', days:3,  agents:['agt-prod-001'],                                       cwe:'CWE-611', desc:'XXE in Adobe Commerce / Magento allows remote code execution.',                            exploit:true,  patch:true,  epss:0.93 },
  { cve_id:'CVE-2024-38112', pkg:'mshtml',            ver:'11.0',   cvss:7.5,  sev:'HIGH',     days:7,  agents:['agt-win-001','agt-win-002'],                          cwe:'CWE-416', desc:'MSHTML platform Windows spoofing vulnerability exploited in wild.',                         exploit:true,  patch:true,  epss:0.75 },
  { cve_id:'CVE-2023-36884', pkg:'ms-office',         ver:'2019',   cvss:8.3,  sev:'HIGH',     days:95, agents:['agt-win-001'],                                        cwe:'CWE-20',  desc:'Office and Windows HTML RCE via specially crafted Office documents.',                       exploit:true,  patch:true,  epss:0.77 },
  { cve_id:'CVE-2024-1709',  pkg:'connectwise',       ver:'23.9.7', cvss:10.0, sev:'CRITICAL', days:11, agents:['agt-prod-003'],                                       cwe:'CWE-288', desc:'Authentication bypass in ConnectWise ScreenConnect.',                                       exploit:true,  patch:true,  epss:0.98 },
  { cve_id:'CVE-2024-29824', pkg:'ivanti-epm',        ver:'2022',   cvss:9.6,  sev:'CRITICAL', days:15, agents:['agt-win-001'],                                        cwe:'CWE-89',  desc:'SQL injection in Ivanti EPM allows unauthenticated RCE.',                                   exploit:true,  patch:true,  epss:0.91 },
  { cve_id:'CVE-2023-48788', pkg:'fortios',           ver:'7.0.9',  cvss:9.8,  sev:'CRITICAL', days:80, agents:['agt-prod-001'],                                       cwe:'CWE-89',  desc:'SQL injection in Fortinet EMS — unauthenticated remote code execution.',                    exploit:true,  patch:true,  epss:0.94 },
  { cve_id:'CVE-2024-5806',  pkg:'moveit-transfer',   ver:'2024.0', cvss:9.1,  sev:'CRITICAL', days:6,  agents:['agt-prod-002'],                                       cwe:'CWE-288', desc:'Improper authentication in MOVEit Transfer SFTP module.',                                   exploit:true,  patch:true,  epss:0.88 },
  { cve_id:'CVE-2024-6670',  pkg:'whatsup-gold',      ver:'23.1',   cvss:9.8,  sev:'CRITICAL', days:8,  agents:['agt-prod-003'],                                       cwe:'CWE-89',  desc:'SQL injection in Progress WhatsUp Gold allows unauthenticated RCE.',                       exploit:true,  patch:true,  epss:0.87 },
  { cve_id:'CVE-2024-20017', pkg:'mediatek-wifi',     ver:'MT7622',  cvss:9.8, sev:'CRITICAL', days:10, agents:['agt-k8s-001'],                                        cwe:'CWE-787', desc:'Out-of-bounds write in MediaTek Wi-Fi chipset firmware.',                                  exploit:false, patch:false, epss:0.62 },
  { cve_id:'CVE-2023-32784', pkg:'keepass',           ver:'2.53',   cvss:7.5,  sev:'HIGH',     days:110,agents:['agt-dev-001','agt-mac-001'],                          cwe:'CWE-316', desc:'KeePass master password leaked in process memory dump.',                                     exploit:true,  patch:true,  epss:0.69 },
  { cve_id:'CVE-2024-24576', pkg:'rust-stdlib',       ver:'1.76.0', cvss:10.0, sev:'CRITICAL', days:16, agents:['agt-prod-001','agt-staging-001'],                     cwe:'CWE-78',  desc:'Command injection in Rust stdlib process::Command on Windows.',                            exploit:false, patch:true,  epss:0.55 },
  { cve_id:'CVE-2024-0519',  pkg:'chromium',          ver:'120.0',  cvss:8.8,  sev:'HIGH',     days:30, agents:['agt-mac-001','agt-win-001'],                          cwe:'CWE-125', desc:'Out of bounds memory access in V8 JavaScript engine.',                                      exploit:true,  patch:true,  epss:0.73 },
  { cve_id:'CVE-2024-21733', pkg:'tomcat',            ver:'10.1.16',cvss:5.3,  sev:'MEDIUM',   days:25, agents:['agt-prod-002','agt-staging-001'],                     cwe:'CWE-200', desc:'Apache Tomcat partial HTTP request allows information disclosure.',                          exploit:false, patch:true,  epss:0.41 },
  { cve_id:'CVE-2023-51074', pkg:'json-path',         ver:'2.8.0',  cvss:7.5,  sev:'HIGH',     days:85, agents:['agt-prod-001','agt-prod-002','agt-staging-001'],       cwe:'CWE-121', desc:'Stack-based buffer overflow in JSON Path library parsing.',                                  exploit:false, patch:true,  epss:0.48 },
  { cve_id:'CVE-2024-21096', pkg:'mysql',             ver:'8.0.35', cvss:4.9,  sev:'MEDIUM',   days:40, agents:['agt-prod-003'],                                       cwe:'CWE-284', desc:'MySQL Server optimizer vulnerability allowing data manipulation.',                           exploit:false, patch:true,  epss:0.22 },
  { cve_id:'CVE-2024-22262', pkg:'spring-web',        ver:'6.1.5',  cvss:7.5,  sev:'HIGH',     days:19, agents:['agt-prod-001','agt-prod-002'],                        cwe:'CWE-601', desc:'URL Parsing with Host Validation in Spring Framework (open redirect).',                    exploit:false, patch:true,  epss:0.45 },
  { cve_id:'CVE-2024-26130', pkg:'cryptography-py',   ver:'42.0.3', cvss:7.5,  sev:'HIGH',     days:13, agents:['agt-prod-001','agt-staging-001','agt-dev-001'],        cwe:'CWE-476', desc:'NULL pointer dereference in python-cryptography PKCS#12 parsing.',                         exploit:false, patch:true,  epss:0.38 },
  { cve_id:'CVE-2024-27282', pkg:'ruby',              ver:'3.3.0',  cvss:6.6,  sev:'MEDIUM',   days:28, agents:['agt-prod-002'],                                       cwe:'CWE-125', desc:'Buffer over-read in Ruby Regex engine.',                                                      exploit:false, patch:true,  epss:0.31 },
  { cve_id:'CVE-2024-4367',  pkg:'pdf-js',            ver:'4.1.0',  cvss:7.5,  sev:'HIGH',     days:22, agents:['agt-prod-001'],                                       cwe:'CWE-20',  desc:'Arbitrary JavaScript execution in PDF.js via font type parameter.',                         exploit:true,  patch:true,  epss:0.72 },
  { cve_id:'CVE-2023-5528',  pkg:'kubernetes',        ver:'1.28.3', cvss:8.8,  sev:'HIGH',     days:120,agents:['agt-k8s-001','agt-k8s-002'],                          cwe:'CWE-20',  desc:'Windows node container filesystem read/write via symlink attack.',                          exploit:false, patch:true,  epss:0.51 },
  { cve_id:'CVE-2024-38063', pkg:'windows-tcpip',     ver:'10.0',   cvss:9.8,  sev:'CRITICAL', days:7,  agents:['agt-win-001','agt-win-002'],                          cwe:'CWE-191', desc:'Windows TCP/IP Remote Code Execution via IPv6 packets.',                                   exploit:false, patch:true,  epss:0.78 },
  { cve_id:'CVE-2023-34048', pkg:'vmware-vcenter',    ver:'8.0.2',  cvss:9.8,  sev:'CRITICAL', days:160,agents:['agt-prod-003'],                                       cwe:'CWE-787', desc:'Out-of-bounds write in VMware vCenter Server.',                                              exploit:true,  patch:true,  epss:0.93 },
  { cve_id:'CVE-2024-3400',  pkg:'panos',             ver:'11.0.4', cvss:10.0, sev:'CRITICAL', days:5,  agents:['agt-prod-001'],                                       cwe:'CWE-77',  desc:'Command injection in PAN-OS GlobalProtect Gateway (Palo Alto).',                           exploit:true,  patch:true,  epss:0.97 },
  { cve_id:'CVE-2024-26257', pkg:'ms-excel',          ver:'16.0',   cvss:7.8,  sev:'HIGH',     days:7,  agents:['agt-win-001'],                                        cwe:'CWE-122', desc:'Microsoft Excel remote code execution via malformed file.',                                   exploit:false, patch:true,  epss:0.62 },
  { cve_id:'CVE-2024-30044', pkg:'sharepoint',        ver:'2019',   cvss:8.8,  sev:'HIGH',     days:7,  agents:['agt-win-001','agt-win-002'],                          cwe:'CWE-502', desc:'Microsoft SharePoint Server Remote Code Execution.',                                         exploit:false, patch:true,  epss:0.67 },
  { cve_id:'CVE-2023-28252', pkg:'windows-clfs',      ver:'10.0',   cvss:7.8,  sev:'HIGH',     days:130,agents:['agt-win-001','agt-win-002'],                          cwe:'CWE-416', desc:'Windows Common Log File System Driver elevation of privilege.',                             exploit:true,  patch:true,  epss:0.74 },
  { cve_id:'CVE-2024-3832',  pkg:'chromium',          ver:'123.0',  cvss:8.8,  sev:'HIGH',     days:21, agents:['agt-mac-001','agt-win-001'],                          cwe:'CWE-843', desc:'Type Confusion in V8 JavaScript engine in Google Chrome.',                                  exploit:true,  patch:true,  epss:0.76 },
  { cve_id:'CVE-2024-28995', pkg:'solarwinds-servu',  ver:'15.4.2', cvss:8.6,  sev:'HIGH',     days:6,  agents:['agt-prod-003'],                                       cwe:'CWE-22',  desc:'Directory traversal in SolarWinds Serv-U.',                                                  exploit:true,  patch:true,  epss:0.81 },
  { cve_id:'CVE-2024-5274',  pkg:'chromium',          ver:'125.0',  cvss:8.8,  sev:'HIGH',     days:4,  agents:['agt-mac-001'],                                        cwe:'CWE-843', desc:'Type Confusion in V8 JavaScript engine — actively exploited zero-day.',                    exploit:true,  patch:true,  epss:0.88 },
];

// SBOM components
const SBOM_COMPONENTS = [
  { name:'openssl',     version:'3.0.11', ecosystem:'system',  license:'Apache-2.0',  cve_count:3, purl:'pkg:deb/debian/openssl@3.0.11'         },
  { name:'libssl',      version:'3.0.11', ecosystem:'system',  license:'Apache-2.0',  cve_count:3, purl:'pkg:deb/debian/libssl@3.0.11'          },
  { name:'glibc',       version:'2.35',   ecosystem:'system',  license:'LGPL-2.1',    cve_count:2, purl:'pkg:deb/debian/libc6@2.35'             },
  { name:'openssh',     version:'9.7p1',  ecosystem:'system',  license:'BSD-2-Clause',cve_count:2, purl:'pkg:deb/debian/openssh-server@9.7p1'   },
  { name:'curl',        version:'8.4.0',  ecosystem:'system',  license:'MIT',         cve_count:1, purl:'pkg:deb/debian/curl@8.4.0'             },
  { name:'django',      version:'4.2.8',  ecosystem:'pypi',    license:'BSD-3-Clause',cve_count:1, purl:'pkg:pypi/django@4.2.8'                 },
  { name:'requests',    version:'2.31.0', ecosystem:'pypi',    license:'Apache-2.0',  cve_count:0, purl:'pkg:pypi/requests@2.31.0'              },
  { name:'cryptography',version:'42.0.3', ecosystem:'pypi',    license:'Apache-2.0',  cve_count:1, purl:'pkg:pypi/cryptography@42.0.3'          },
  { name:'express',     version:'4.18.2', ecosystem:'npm',     license:'MIT',         cve_count:0, purl:'pkg:npm/express@4.18.2'                },
  { name:'lodash',      version:'4.17.21',ecosystem:'npm',     license:'MIT',         cve_count:0, purl:'pkg:npm/lodash@4.17.21'                },
  { name:'axios',       version:'1.6.2',  ecosystem:'npm',     license:'MIT',         cve_count:0, purl:'pkg:npm/axios@1.6.2'                   },
  { name:'log4j-core',  version:'2.17.1', ecosystem:'maven',   license:'Apache-2.0',  cve_count:0, purl:'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1' },
  { name:'spring-web',  version:'6.1.5',  ecosystem:'maven',   license:'Apache-2.0',  cve_count:1, purl:'pkg:maven/org.springframework/spring-web@6.1.5'        },
  { name:'tomcat',      version:'10.1.16',ecosystem:'maven',   license:'Apache-2.0',  cve_count:1, purl:'pkg:maven/org.apache.tomcat/tomcat@10.1.16'            },
  { name:'go',          version:'1.21.6', ecosystem:'golang',  license:'BSD-3-Clause',cve_count:0, purl:'pkg:golang/go@1.21.6'                  },
  { name:'rust',        version:'1.76.0', ecosystem:'cargo',   license:'MIT/Apache',  cve_count:1, purl:'pkg:cargo/rust-std@1.76.0'             },
  { name:'ruby',        version:'3.3.0',  ecosystem:'gem',     license:'Ruby',        cve_count:1, purl:'pkg:gem/ruby@3.3.0'                    },
  { name:'nginx',       version:'1.25.3', ecosystem:'system',  license:'BSD-2-Clause',cve_count:0, purl:'pkg:deb/debian/nginx@1.25.3'           },
  { name:'postgres',    version:'16.2',   ecosystem:'system',  license:'PostgreSQL',  cve_count:0, purl:'pkg:deb/debian/postgresql-16@16.2'     },
  { name:'redis',       version:'7.2.3',  ecosystem:'system',  license:'BSD-3-Clause',cve_count:0, purl:'pkg:deb/debian/redis@7.2.3'            },
];

// DAST findings
const DAST_FINDINGS = [
  { id:'dast-001', endpoint:'/api/v1/users/search',   method:'GET',  attack:'SQL Injection',         severity:'CRITICAL', cvss:9.1, evidence:'param=1 OR 1=1 returned all rows',       status:'open',     path:'/api/v1/users/search?q=1%27+OR+%271%27%3D%271' },
  { id:'dast-002', endpoint:'/api/v1/auth/login',     method:'POST', attack:'SQL Injection',         severity:'CRITICAL', cvss:9.1, evidence:'admin\' --  bypassed password check',    status:'open',     path:'/api/v1/auth/login' },
  { id:'dast-003', endpoint:'/search',                method:'GET',  attack:'Reflected XSS',         severity:'HIGH',     cvss:7.2, evidence:'<script>alert(1)</script> reflected',    status:'open',     path:'/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' },
  { id:'dast-004', endpoint:'/profile',               method:'POST', attack:'Stored XSS',            severity:'HIGH',     cvss:8.1, evidence:'Payload persisted in bio field',         status:'remediated',path:'/profile' },
  { id:'dast-005', endpoint:'/api/v1/export',         method:'GET',  attack:'SSRF',                  severity:'HIGH',     cvss:7.5, evidence:'url=http://169.254.169.254/latest/meta-data/', status:'open', path:'/api/v1/export?url=...' },
  { id:'dast-006', endpoint:'/api/v1/import',         method:'POST', attack:'XXE',                   severity:'HIGH',     cvss:7.5, evidence:'DOCTYPE entity exfiltrated /etc/passwd', status:'open',    path:'/api/v1/import' },
  { id:'dast-007', endpoint:'/api/v1/template',       method:'POST', attack:'SSTI',                  severity:'HIGH',     cvss:8.8, evidence:'{{7*7}} rendered as 49',                 status:'open',     path:'/api/v1/template' },
  { id:'dast-008', endpoint:'/api/v1/exec',           method:'POST', attack:'Command Injection',     severity:'CRITICAL', cvss:9.8, evidence:'ping;whoami returned "www-data"',         status:'open',     path:'/api/v1/exec' },
  { id:'dast-009', endpoint:'/api/v1/files',          method:'GET',  attack:'Path Traversal',        severity:'HIGH',     cvss:7.5, evidence:'../../../etc/passwd read successfully',  status:'open',     path:'/api/v1/files?path=../../etc/passwd' },
  { id:'dast-010', endpoint:'/api/v1/users/2',        method:'GET',  attack:'Broken Object Auth',    severity:'HIGH',     cvss:6.5, evidence:'Accessed user 2 resources as user 1',   status:'open',     path:'/api/v1/users/2' },
  { id:'dast-011', endpoint:'/api/v1/admin',          method:'GET',  attack:'Broken Access Control', severity:'CRITICAL', cvss:9.0, evidence:'Admin panel accessible without admin role', status:'open',  path:'/api/v1/admin' },
  { id:'dast-012', endpoint:'/api/v1/sessions',       method:'GET',  attack:'Insecure Deserialization',severity:'HIGH',   cvss:8.1, evidence:'Serialized Java object executed arbitrary code', status:'open', path:'/api/v1/sessions' },
  { id:'dast-013', endpoint:'/login',                 method:'POST', attack:'Broken Auth',           severity:'MEDIUM',   cvss:6.5, evidence:'No rate limiting on login endpoint',     status:'open',     path:'/login' },
  { id:'dast-014', endpoint:'/api/v1/health',         method:'GET',  attack:'Info Disclosure',       severity:'LOW',      cvss:3.1, evidence:'Exposed internal stack traces & versions',status:'open',    path:'/api/v1/health' },
  { id:'dast-015', endpoint:'/api/v1/graphql',        method:'POST', attack:'NoSQL Injection',       severity:'HIGH',     cvss:7.3, evidence:'{"$gt":""} bypassed authentication',     status:'open',     path:'/api/v1/graphql' },
];

// 30-day trend (new vs resolved per day, last 30 days)
const TREND_30D = (() => {
  const days = 30;
  const now = new Date();
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now - i * 86400000);
    out.push({
      date: d.toISOString().slice(0, 10),
      new_vulns:     [4,2,8,5,1,12,3,6,2,9,4,7,2,5,11,3,1,8,5,3,14,2,7,4,9,3,6,2,5,8][days-1-i] || 3,
      resolved_vulns:[2,3,5,4,2,8,2,4,3,6,3,5,1,4,7,2,2,5,4,2,9,1,5,3,6,2,4,1,4,5][days-1-i] || 2,
    });
  }
  return out;
})();

function buildMockVulnerabilities() {
  const now = new Date();

  // Enrich CVE data with timestamps
  const vulnerabilities = CVE_DATA.map((v, i) => ({
    ...v,
    id:               i + 1,
    status:           v.days > 90 ? 'overdue' : v.days > 30 ? 'open' : 'new',
    discovered_at:    new Date(+now - v.days * 86400000).toISOString(),
    sla_deadline:     new Date(+now + (v.sev === 'CRITICAL' ? 7 : v.sev === 'HIGH' ? 14 : 30) * 86400000 - v.days * 86400000).toISOString(),
    sla_breached:     (v.sev === 'CRITICAL' && v.days > 7) || (v.sev === 'HIGH' && v.days > 14) || (v.sev === 'MEDIUM' && v.days > 30),
    affected_assets:  v.agents.length,
    affected_agents:  v.agents,
  }));

  // Severity counts
  const sevCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  vulnerabilities.forEach(v => { sevCount[v.sev] = (sevCount[v.sev] || 0) + 1; });

  // Package frequency
  const pkgMap = {};
  vulnerabilities.forEach(v => {
    pkgMap[v.pkg] = (pkgMap[v.pkg] || 0) + 1;
  });
  const topPackages = Object.entries(pkgMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, count]) => ({ name, count }));

  // Asset enrichment
  const assetVulnMap = {};
  vulnerabilities.forEach(v => {
    v.affected_agents.forEach(aid => {
      if (!assetVulnMap[aid]) assetVulnMap[aid] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 };
      assetVulnMap[aid][v.sev]++;
      assetVulnMap[aid].total++;
    });
  });

  const assets = AGENTS.map(a => {
    const vc = assetVulnMap[a.agent_id] || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 };
    const riskScore = Math.min(100, Math.round(
      vc.CRITICAL * 10 + vc.HIGH * 4 + vc.MEDIUM * 1.5 + vc.LOW * 0.5
    ));
    const lastSeen = new Date(+now + a.last_seen * 86400000);
    return {
      ...a,
      last_seen_ts:    lastSeen.toISOString(),
      packages_scanned: 180 + Math.abs(a.last_seen) * 3,
      vuln_critical:   vc.CRITICAL,
      vuln_high:       vc.HIGH,
      vuln_medium:     vc.MEDIUM,
      vuln_low:        vc.LOW,
      vuln_total:      vc.total,
      risk_score:      riskScore,
      risk_level:      riskScore >= 80 ? 'CRITICAL' : riskScore >= 60 ? 'HIGH' : riskScore >= 30 ? 'MEDIUM' : 'LOW',
    };
  });

  // CVSS distribution buckets
  const cvssBuckets = { '9-10': 0, '7-9': 0, '4-7': 0, '0-4': 0 };
  vulnerabilities.forEach(v => {
    if (v.cvss >= 9) cvssBuckets['9-10']++;
    else if (v.cvss >= 7) cvssBuckets['7-9']++;
    else if (v.cvss >= 4) cvssBuckets['4-7']++;
    else cvssBuckets['0-4']++;
  });

  // Age distribution
  const ageBuckets = { '<7d': 0, '7-30d': 0, '30-90d': 0, '>90d': 0 };
  vulnerabilities.forEach(v => {
    if (v.days < 7)        ageBuckets['<7d']++;
    else if (v.days < 30)  ageBuckets['7-30d']++;
    else if (v.days < 90)  ageBuckets['30-90d']++;
    else                   ageBuckets['>90d']++;
  });

  // SLA status
  const slaBreach  = vulnerabilities.filter(v => v.sla_breached).length;
  const slaOK      = vulnerabilities.length - slaBreach;

  // Remediation queue — prioritized by CVSS × exploit_available × days_open
  const remediationQueue = [...vulnerabilities]
    .sort((a, b) => {
      const scoreA = a.cvss * (a.exploit ? 2 : 1) * Math.log1p(a.days);
      const scoreB = b.cvss * (b.exploit ? 2 : 1) * Math.log1p(b.days);
      return scoreB - scoreA;
    })
    .slice(0, 20)
    .map(v => ({
      cve_id:          v.cve_id,
      pkg:             v.pkg,
      severity:        v.sev,
      cvss:            v.cvss,
      epss:            v.epss,
      exploit:         v.exploit,
      patch_available: v.patch,
      affected_assets: v.affected_assets,
      days_open:       v.days,
      sla_breached:    v.sla_breached,
      priority_score:  +(v.cvss * (v.exploit ? 2 : 1) * Math.log1p(v.days)).toFixed(1),
      status:          v.sla_breached ? 'overdue' : v.days <= 7 ? 'new' : 'open',
    }));

  // Summary KPIs
  const totalVulns    = vulnerabilities.length;
  const criticalCount = sevCount.CRITICAL;
  const highCount     = sevCount.HIGH;
  const affectedAssets = assets.filter(a => a.vuln_total > 0).length;
  const activeAgents  = AGENTS.filter(a => a.status === 'active').length;
  const mttr          = 18; // days, mock
  const patchCoverage = Math.round((vulnerabilities.filter(v => v.patch).length / totalVulns) * 100);

  return {
    _source: 'mock',
    summary: {
      total_vulnerabilities: totalVulns,
      critical_count:        criticalCount,
      high_count:            highCount,
      medium_count:          sevCount.MEDIUM,
      low_count:             sevCount.LOW,
      affected_assets:       affectedAssets,
      total_agents:          AGENTS.length,
      active_agents:         activeAgents,
      sla_breached:          slaBreach,
      sla_on_track:          slaOK,
      mean_time_to_remediate: mttr,
      patch_coverage_pct:    patchCoverage,
      exploitable_count:     vulnerabilities.filter(v => v.exploit).length,
    },
    severity_breakdown: sevCount,
    cvss_distribution:  cvssBuckets,
    age_distribution:   ageBuckets,
    top_packages:       topPackages,
    trend_30d:          TREND_30D,
    vulnerabilities,
    assets,
    sbom:               SBOM_COMPONENTS,
    dast:               DAST_FINDINGS,
    remediation_queue:  remediationQueue,
  };
}

// ── Route handler ─────────────────────────────────────────────────────────────
export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const tenantId = searchParams.get('tenant_id') || '';

  // Try live engine dashboard
  const dashUrl = `${NLB_URL}/vulnerability/api/v1/reports/dashboard?tenant_id=${tenantId}`;
  let liveData = await tryFetch(dashUrl);

  if (isDegenerate(liveData)) {
    return NextResponse.json(buildMockVulnerabilities(), {
      headers: { 'X-Vuln-Source': 'mock' },
    });
  }

  return NextResponse.json({ ...liveData, _source: 'live' }, {
    headers: { 'X-Vuln-Source': 'live' },
  });
}
