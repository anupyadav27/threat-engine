#!/usr/bin/env python3
"""CIEM CRUD Round 3 — push GCP/OCI/IBM to 500+"""
import json, os, hashlib

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

MITRE = {
    'create': ('["persistence"]','["T1136"]','persistence'),
    'delete': ('["impact"]','["T1485"]','impact'),
    'modify': ('["persistence"]','["T1098"]','persistence'),
    'read':   ('["discovery"]','["T1526"]','discovery'),
}
SEV   = {'create':'high','delete':'high','modify':'medium','read':'low'}
RISK  = {'create':70,'delete':75,'modify':55,'read':30}
SRC   = {'gcp':'gcp_audit','oci':'oci_audit','ibm':'ibm_activity'}
ACTS  = {
    'create':['create','insert','add','put','write','register','attach','launch','allocate','deploy','enable','start','submit'],
    'delete':['delete','remove','deregister','detach','terminate','disable','cancel','revoke','destroy','drop','purge','stop'],
    'modify':['update','modify','change','set','patch','replace','rotate','restore','resize','scale','tag','reset','flush','alter'],
    'read':  ['get','list','describe','read','show','query','search','export','fetch'],
}

def infer_cat(s):
    t = s.lower()
    for cat, words in ACTS.items():
        if any(w in t for w in words):
            return cat
    return 'modify'

def sql(s): return "'" + s.replace("'","''") + "'"

def cfg_gcp(uri, method):
    return sql(json.dumps({"conditions":{"all":[
        {"op":"equals","field":"source_type","value":"gcp_audit"},
        {"op":"equals","field":"service","value":uri},
        {"op":"contains","field":"operation","value":method},
    ]}},separators=(',',':')))

def cfg_oci(cadf, op):
    return sql(json.dumps({"conditions":{"all":[
        {"op":"equals","field":"source_type","value":"oci_audit"},
        {"op":"equals","field":"service","value":cadf},
        {"op":"equals","field":"operation","value":op},
    ]}},separators=(',',':')))

def cfg_ibm(svc, verb):
    return sql(json.dumps({"conditions":{"all":[
        {"op":"equals","field":"source_type","value":"ibm_activity"},
        {"op":"equals","field":"service","value":svc},
        {"op":"contains","field":"operation","value":f".{verb}"},
    ]}},separators=(',',':')))

def emit(f, rid, svc, provider, title, desc, cat, cfg, log_event):
    tac, tec, dom = MITRE[cat]
    sev, risk, log_src = SEV[cat], RISK[cat], SRC[provider]
    f.write(
        f"INSERT INTO rule_checks (rule_id,service,provider,check_type,is_active,check_config)\n"
        f"VALUES ({sql(rid)},{sql(svc)},{sql(provider)},'log',true,{cfg})\n"
        f"ON CONFLICT DO NOTHING;\n\n"
        f"INSERT INTO rule_metadata (\n"
        f"  rule_id,service,provider,severity,title,description,\n"
        f"  domain,subcategory,log_source_type,audit_log_event,action_category,\n"
        f"  rule_source,engines,primary_engine,mitre_tactics,mitre_techniques,risk_score,quality,csp\n"
        f") VALUES (\n"
        f"  {sql(rid)},{sql(svc)},{sql(provider)},\n"
        f"  {sql(sev)},{sql(title)},{sql(desc)},\n"
        f"  {sql(dom)},{sql(cat)},{sql(log_src)},\n"
        f"  {sql(log_event)},{sql(cat)},\n"
        f"  'log','{{\"ciem_engine\"}}','ciem_engine',\n"
        f"  '{tac}','{tec}',{risk},'auto',{sql(provider)}\n"
        f") ON CONFLICT DO NOTHING;\n\n"
    )

# ── GCP ──────────────────────────────────────────────────────────────────────
def gen_gcp(out_dir):
    path = os.path.join(out_dir, "ciem_gcp_crud_r3.sql")
    n = 0
    rules = [
        # Firebase
        ("firebase.googleapis.com","firebase","Firebase Projects","AddFirebase","Add Firebase to GCP Project"),
        ("firebase.googleapis.com","firebase","Firebase Projects","RemoveAnalytics","Remove Firebase Analytics"),
        ("firebasedatabase.googleapis.com","firebasedatabase","Firebase RTDB","CreateDatabaseInstance","Create Firebase Realtime Database"),
        ("firebasedatabase.googleapis.com","firebasedatabase","Firebase RTDB","DeleteDatabaseInstance","Delete Firebase Realtime Database"),
        ("firebasehosting.googleapis.com","firebasehosting","Firebase Hosting","CreateSite","Create Firebase Hosting Site"),
        ("firebasehosting.googleapis.com","firebasehosting","Firebase Hosting","DeleteSite","Delete Firebase Hosting Site"),
        ("firebasestorage.googleapis.com","firebasestorage","Firebase Storage","AddFirebase","Link Firebase Storage Bucket"),
        # Certificate Manager
        ("certificatemanager.googleapis.com","certificatemanager","Certificate Maps","CreateCertificateMap","Create Certificate Map"),
        ("certificatemanager.googleapis.com","certificatemanager","Certificate Maps","DeleteCertificateMap","Delete Certificate Map"),
        ("certificatemanager.googleapis.com","certificatemanager","Certificates","CreateCertificate","Create Certificate Manager Certificate"),
        ("certificatemanager.googleapis.com","certificatemanager","Certificates","DeleteCertificate","Delete Certificate Manager Certificate"),
        # Cloud Domains
        ("domains.googleapis.com","domains","Cloud Domains","RegisterDomain","Register Cloud Domain"),
        ("domains.googleapis.com","domains","Cloud Domains","TransferDomain","Transfer Cloud Domain"),
        ("domains.googleapis.com","domains","Cloud Domains","DeleteRegistration","Delete Domain Registration"),
        # Workflows
        ("workflows.googleapis.com","workflows","Cloud Workflows","CreateWorkflow","Create Cloud Workflow"),
        ("workflows.googleapis.com","workflows","Cloud Workflows","DeleteWorkflow","Delete Cloud Workflow"),
        ("workflows.googleapis.com","workflows","Cloud Workflows","UpdateWorkflow","Update Cloud Workflow"),
        ("workflowexecutions.googleapis.com","workflowexecutions","Workflow Executions","CreateExecution","Execute Cloud Workflow"),
        ("workflowexecutions.googleapis.com","workflowexecutions","Workflow Executions","CancelExecution","Cancel Cloud Workflow Execution"),
        # VPC Access (Serverless VPC)
        ("vpcaccess.googleapis.com","vpcaccess","VPC Access Connectors","CreateConnector","Create Serverless VPC Connector"),
        ("vpcaccess.googleapis.com","vpcaccess","VPC Access Connectors","DeleteConnector","Delete Serverless VPC Connector"),
        # Bare Metal Solution
        ("baremetalsolution.googleapis.com","baremetalsolution","Bare Metal Servers","ResetInstance","Reset Bare Metal Server"),
        ("baremetalsolution.googleapis.com","baremetalsolution","Bare Metal Volumes","ResizeVolume","Resize Bare Metal Volume"),
        # Document AI
        ("documentai.googleapis.com","documentai","Document AI Processors","CreateProcessor","Create Document AI Processor"),
        ("documentai.googleapis.com","documentai","Document AI Processors","DeleteProcessor","Delete Document AI Processor"),
        ("documentai.googleapis.com","documentai","Document AI Processors","EnableProcessor","Enable Document AI Processor"),
        ("documentai.googleapis.com","documentai","Document AI Processors","DisableProcessor","Disable Document AI Processor"),
        # Eventarc
        ("eventarc.googleapis.com","eventarc","Eventarc Triggers","CreateTrigger","Create Eventarc Trigger"),
        ("eventarc.googleapis.com","eventarc","Eventarc Triggers","DeleteTrigger","Delete Eventarc Trigger"),
        ("eventarc.googleapis.com","eventarc","Eventarc Triggers","UpdateTrigger","Update Eventarc Trigger"),
        # GKE Hub / Fleet
        ("gkehub.googleapis.com","gkehub","GKE Fleet Memberships","CreateMembership","Register Cluster to GKE Fleet"),
        ("gkehub.googleapis.com","gkehub","GKE Fleet Memberships","DeleteMembership","Remove Cluster from GKE Fleet"),
        ("gkehub.googleapis.com","gkehub","Fleet Features","CreateFeature","Enable GKE Fleet Feature"),
        ("gkehub.googleapis.com","gkehub","Fleet Features","DeleteFeature","Disable GKE Fleet Feature"),
        # Binary Authorization
        ("binaryauthorization.googleapis.com","binaryauthorization","Binauthz Policy","UpdatePolicy","Update Binary Authorization Policy"),
        ("binaryauthorization.googleapis.com","binaryauthorization","Binauthz Attestors","CreateAttestor","Create Binary Authorization Attestor"),
        ("binaryauthorization.googleapis.com","binaryauthorization","Binauthz Attestors","DeleteAttestor","Delete Binary Authorization Attestor"),
        # OS Config / Patch
        ("osconfig.googleapis.com","osconfig","Patch Deployments","CreatePatchDeployment","Create OS Patch Deployment"),
        ("osconfig.googleapis.com","osconfig","Patch Deployments","DeletePatchDeployment","Delete OS Patch Deployment"),
        ("osconfig.googleapis.com","osconfig","OS Policy Assignments","CreateOSPolicyAssignment","Create OS Policy Assignment"),
        # Assured Workloads
        ("assuredworkloads.googleapis.com","assuredworkloads","Assured Workloads","CreateWorkload","Create Assured Workload"),
        ("assuredworkloads.googleapis.com","assuredworkloads","Assured Workloads","DeleteWorkload","Delete Assured Workload"),
        ("assuredworkloads.googleapis.com","assuredworkloads","Assured Workloads","UpdateWorkload","Update Assured Workload"),
        # Network Security
        ("networksecurity.googleapis.com","networksecurity","AuthZ Policies","CreateAuthorizationPolicy","Create Network Authorization Policy"),
        ("networksecurity.googleapis.com","networksecurity","AuthZ Policies","DeleteAuthorizationPolicy","Delete Network Authorization Policy"),
        ("networksecurity.googleapis.com","networksecurity","TLS Inspection","CreateTlsInspectionPolicy","Create TLS Inspection Policy"),
        ("networksecurity.googleapis.com","networksecurity","ServerTLS Policies","CreateServerTlsPolicy","Create Server TLS Policy"),
        # Cloud Armor extra
        ("compute.googleapis.com","compute","Security Policies Rules","addRule","Add Cloud Armor Security Policy Rule"),
        ("compute.googleapis.com","compute","Security Policies Rules","patchRule","Update Cloud Armor Security Policy Rule"),
        ("compute.googleapis.com","compute","Security Policies Rules","removeRule","Remove Cloud Armor Security Policy Rule"),
        # AlloyDB
        ("alloydb.googleapis.com","alloydb","AlloyDB Backups","DeleteBackup","Delete AlloyDB Backup"),
        ("alloydb.googleapis.com","alloydb","AlloyDB Users","CreateUser","Create AlloyDB Database User"),
        ("alloydb.googleapis.com","alloydb","AlloyDB Users","DeleteUser","Delete AlloyDB Database User"),
        # Access Context Manager
        ("accesscontextmanager.googleapis.com","accesscontextmanager","Access Policies","CreateAccessPolicy","Create Access Context Manager Policy"),
        ("accesscontextmanager.googleapis.com","accesscontextmanager","Access Levels","CreateAccessLevel","Create VPC Service Control Access Level"),
        ("accesscontextmanager.googleapis.com","accesscontextmanager","Service Perimeters","CreateServicePerimeter","Create VPC Service Control Perimeter"),
        ("accesscontextmanager.googleapis.com","accesscontextmanager","Service Perimeters","DeleteServicePerimeter","Delete VPC Service Control Perimeter"),
        ("accesscontextmanager.googleapis.com","accesscontextmanager","Service Perimeters","UpdateServicePerimeter","Update VPC Service Control Perimeter"),
        # Pub/Sub Lite
        ("pubsublite.googleapis.com","pubsublite","Pub/Sub Lite Topics","CreateTopic","Create Pub/Sub Lite Topic"),
        ("pubsublite.googleapis.com","pubsublite","Pub/Sub Lite Topics","DeleteTopic","Delete Pub/Sub Lite Topic"),
        ("pubsublite.googleapis.com","pubsublite","Pub/Sub Lite Subscriptions","CreateSubscription","Create Pub/Sub Lite Subscription"),
        # Cloud Spanner more ops
        ("spanner.googleapis.com","spanner","Spanner Instance Configs","CreateInstanceConfig","Create Spanner Instance Config"),
        ("spanner.googleapis.com","spanner","Spanner Sessions","BatchCreateSessions","Batch Create Spanner Sessions"),
        # Looker
        ("looker.googleapis.com","looker","Looker Instances","CreateInstance","Create Looker Instance"),
        ("looker.googleapis.com","looker","Looker Instances","DeleteInstance","Delete Looker Instance"),
        ("looker.googleapis.com","looker","Looker Instances","UpdateInstance","Update Looker Instance"),
        # GCS more ops
        ("storage.googleapis.com","storage","GCS Bucket Notifications","storage.notifications.create","Create GCS Bucket Notification"),
        ("storage.googleapis.com","storage","GCS Bucket ACLs","storage.bucketAccessControls.create","Create GCS Bucket ACL Entry"),
        ("storage.googleapis.com","storage","GCS Object ACLs","storage.objectAccessControls.create","Create GCS Object ACL Entry"),
        # Compute more ops
        ("compute.googleapis.com","compute","Compute VPN Tunnels","insert","Create VPN Tunnel"),
        ("compute.googleapis.com","compute","Compute VPN Tunnels","delete","Delete VPN Tunnel"),
        ("compute.googleapis.com","compute","Compute Forwarding Rules","insert","Create Forwarding Rule"),
        ("compute.googleapis.com","compute","Compute Forwarding Rules","delete","Delete Forwarding Rule"),
        ("compute.googleapis.com","compute","Compute Health Checks","insert","Create Compute Health Check"),
        ("compute.googleapis.com","compute","Compute Target Pools","insert","Create Compute Target Pool"),
        ("compute.googleapis.com","compute","Compute Managed Instance Groups","insert","Create Managed Instance Group"),
        ("compute.googleapis.com","compute","Compute Managed Instance Groups","delete","Delete Managed Instance Group"),
    ]
    with open(path, "w") as f:
        f.write("-- GCP CRUD round 3\n")
        for uri, svc, res, method, display in rules:
            cat = infer_cat(method + " " + display)
            rid = f"log.gcp.{svc}.{hashlib.md5((uri+method).encode()).hexdigest()[:8]}"
            title = f"GCP {res}: {display}"
            emit(f, rid, uri, "gcp", title, f"Detected {method} on {res} via GCP Audit Logs.", cat, cfg_gcp(uri, method), method)
            n += 1
    print(f"GCP CRUD r3: {n} → {path}")
    return n

# ── OCI ──────────────────────────────────────────────────────────────────────
def gen_oci(out_dir):
    path = os.path.join(out_dir, "ciem_oci_crud_r3.sql")
    n = 0
    rules = [
        # DevOps
        ("com.oraclecloud.devops","devops","DevOps Projects","CreateProject","Create DevOps Project"),
        ("com.oraclecloud.devops","devops","DevOps Projects","DeleteProject","Delete DevOps Project"),
        ("com.oraclecloud.devops","devops","DevOps Pipelines","CreateDeployPipeline","Create Deployment Pipeline"),
        ("com.oraclecloud.devops","devops","DevOps Pipelines","DeleteDeployPipeline","Delete Deployment Pipeline"),
        ("com.oraclecloud.devops","devops","DevOps Pipelines","RunDeploymentPipeline","Run Deployment Pipeline"),
        ("com.oraclecloud.devops","devops","DevOps Build Pipelines","CreateBuildPipeline","Create Build Pipeline"),
        ("com.oraclecloud.devops","devops","DevOps Build Runs","RunBuildPipeline","Run Build Pipeline"),
        ("com.oraclecloud.devops","devops","DevOps Repositories","CreateRepository","Create Code Repository"),
        ("com.oraclecloud.devops","devops","DevOps Artifacts","CreateDeployArtifact","Create Deployment Artifact"),
        # WAF extra ops
        ("com.oraclecloud.waf","waf","WAF Policies","CreateWebAppFirewallPolicy","Create WAF Policy"),
        ("com.oraclecloud.waf","waf","WAF Policies","DeleteWebAppFirewallPolicy","Delete WAF Policy"),
        ("com.oraclecloud.waf","waf","WAF Policies","UpdateWebAppFirewallPolicy","Update WAF Policy"),
        ("com.oraclecloud.waf","waf","WAF Protection Capabilities","UpdateNetworkAddressList","Update WAF Network Address List"),
        # API Gateway extra ops
        ("com.oraclecloud.apigateway","apigateway","API Gateways","CreateGateway","Create API Gateway"),
        ("com.oraclecloud.apigateway","apigateway","API Gateways","DeleteGateway","Delete API Gateway"),
        ("com.oraclecloud.apigateway","apigateway","API Gateways","UpdateGateway","Update API Gateway"),
        ("com.oraclecloud.apigateway","apigateway","API Deployments","CreateDeployment","Create API Deployment"),
        ("com.oraclecloud.apigateway","apigateway","API Deployments","DeleteDeployment","Delete API Deployment"),
        ("com.oraclecloud.apigateway","apigateway","API Certificates","CreateCertificate","Create API Gateway Certificate"),
        # Load Balancer extra
        ("com.oraclecloud.loadbalancer","loadbalancer","Load Balancers","CreateLoadBalancer","Create Load Balancer"),
        ("com.oraclecloud.loadbalancer","loadbalancer","Load Balancers","DeleteLoadBalancer","Delete Load Balancer"),
        ("com.oraclecloud.loadbalancer","loadbalancer","LB Backends","CreateBackendSet","Create LB Backend Set"),
        ("com.oraclecloud.loadbalancer","loadbalancer","LB Backends","DeleteBackendSet","Delete LB Backend Set"),
        ("com.oraclecloud.loadbalancer","loadbalancer","LB Listeners","CreateListener","Create LB Listener"),
        ("com.oraclecloud.loadbalancer","loadbalancer","LB Certificates","CreateCertificate","Create LB Certificate"),
        # Bastion extra
        ("com.oraclecloud.bastion","bastion","Bastions","CreateBastion","Create OCI Bastion"),
        ("com.oraclecloud.bastion","bastion","Bastions","DeleteBastion","Delete OCI Bastion"),
        ("com.oraclecloud.bastion","bastion","Bastions","UpdateBastion","Update OCI Bastion"),
        ("com.oraclecloud.bastion","bastion","Bastion Sessions","DeleteSession","Delete Bastion Session"),
        # Functions extra
        ("com.oraclecloud.functions","functions","Function Applications","CreateApplication","Create Functions Application"),
        ("com.oraclecloud.functions","functions","Function Applications","DeleteApplication","Delete Functions Application"),
        ("com.oraclecloud.functions","functions","Function Applications","UpdateApplication","Update Functions Application"),
        ("com.oraclecloud.functions","functions","Functions","CreateFunction","Create Function"),
        ("com.oraclecloud.functions","functions","Functions","DeleteFunction","Delete Function"),
        ("com.oraclecloud.functions","functions","Functions","UpdateFunction","Update Function"),
        # Streaming extra
        ("com.oraclecloud.streaming","streaming","Streams","CreateStream","Create OCI Stream"),
        ("com.oraclecloud.streaming","streaming","Streams","DeleteStream","Delete OCI Stream"),
        ("com.oraclecloud.streaming","streaming","Streams","UpdateStream","Update OCI Stream"),
        ("com.oraclecloud.streaming","streaming","Stream Pools","CreateStreamPool","Create Stream Pool"),
        ("com.oraclecloud.streaming","streaming","Stream Pools","DeleteStreamPool","Delete Stream Pool"),
        ("com.oraclecloud.streaming","streaming","Connect Harnesses","CreateConnectHarness","Create Kafka Connect Harness"),
        # Service Connector extra
        ("com.oraclecloud.serviceconnector","sch","Service Connectors","UpdateServiceConnector","Update Service Connector"),
        ("com.oraclecloud.serviceconnector","sch","Service Connectors","DeleteServiceConnector","Delete Service Connector"),
        # ONS (Notifications)
        ("com.oraclecloud.ons","ons","Notification Topics","CreateTopic","Create Notification Topic"),
        ("com.oraclecloud.ons","ons","Notification Topics","DeleteTopic","Delete Notification Topic"),
        ("com.oraclecloud.ons","ons","Notification Topics","UpdateTopic","Update Notification Topic"),
        ("com.oraclecloud.ons","ons","Subscriptions","CreateSubscription","Create Notification Subscription"),
        ("com.oraclecloud.ons","ons","Subscriptions","DeleteSubscription","Delete Notification Subscription"),
        # Monitoring extra
        ("com.oraclecloud.monitoring","monitoring","Alarms","CreateAlarm","Create Monitoring Alarm"),
        ("com.oraclecloud.monitoring","monitoring","Alarms","DeleteAlarm","Delete Monitoring Alarm"),
        ("com.oraclecloud.monitoring","monitoring","Alarms","UpdateAlarm","Update Monitoring Alarm"),
        ("com.oraclecloud.monitoring","monitoring","Alarms","SuppressAlarm","Suppress Monitoring Alarm"),
        # Logging extra
        ("com.oraclecloud.logging","logging","Log Groups","CreateLogGroup","Create Log Group"),
        ("com.oraclecloud.logging","logging","Log Groups","DeleteLogGroup","Delete Log Group"),
        ("com.oraclecloud.logging","logging","Log Groups","UpdateLogGroup","Update Log Group"),
        ("com.oraclecloud.logging","logging","Logs","CreateLog","Create Log"),
        ("com.oraclecloud.logging","logging","Logs","DeleteLog","Delete Log"),
        ("com.oraclecloud.logging","logging","Logs","UpdateLog","Update Log"),
        # Resource Manager extra
        ("com.oraclecloud.resourcemanager","resourcemanager","Stacks","CreateStack","Create Resource Manager Stack"),
        ("com.oraclecloud.resourcemanager","resourcemanager","Stacks","DeleteStack","Delete Resource Manager Stack"),
        ("com.oraclecloud.resourcemanager","resourcemanager","Stacks","UpdateStack","Update Resource Manager Stack"),
        ("com.oraclecloud.resourcemanager","resourcemanager","Jobs","CancelJob","Cancel Resource Manager Job"),
        # Events extra
        ("com.oraclecloud.events","events","Event Rules","UpdateRule","Update Events Rule"),
        ("com.oraclecloud.events","events","Event Rules","DeleteRule","Delete Events Rule"),
        # Redis extra
        ("com.oraclecloud.redis","redis","Redis Clusters","CreateRedisCluster","Create OCI Redis Cluster"),
        ("com.oraclecloud.redis","redis","Redis Clusters","DeleteRedisCluster","Delete OCI Redis Cluster"),
        ("com.oraclecloud.redis","redis","Redis Clusters","UpdateRedisCluster","Update OCI Redis Cluster"),
        # Vault extra ops
        ("com.oraclecloud.vaultmng","vault","Vaults","CreateVault","Create OCI Vault"),
        ("com.oraclecloud.vaultmng","vault","Vaults","UpdateVault","Update OCI Vault"),
        ("com.oraclecloud.vaultmng","vault","Keys","CreateKey","Create Vault Key"),
        ("com.oraclecloud.vaultmng","vault","Keys","UpdateKey","Update Vault Key"),
        ("com.oraclecloud.vaultmng","vault","Secrets","CreateSecret","Create Vault Secret"),
        ("com.oraclecloud.vaultmng","vault","Secrets","UpdateSecret","Update Vault Secret"),
        # Data Catalog extra
        ("com.oraclecloud.datacatalog","datacatalog","Data Catalogs","CreateCatalog","Create Data Catalog"),
        ("com.oraclecloud.datacatalog","datacatalog","Data Catalogs","DeleteCatalog","Delete Data Catalog"),
        ("com.oraclecloud.datacatalog","datacatalog","Data Connections","CreateConnection","Create Data Catalog Connection"),
    ]
    with open(path, "w") as f:
        f.write("-- OCI CRUD round 3\n")
        for cadf, svc, res, op, display in rules:
            cat = infer_cat(op + " " + display)
            rid = f"log.oci.{svc}.{hashlib.md5((cadf+op).encode()).hexdigest()[:8]}"
            title = f"OCI {res}: {display}"
            emit(f, rid, cadf, "oci", title, f"Detected {op} on {res} via OCI Audit Logs.", cat, cfg_oci(cadf, op), op)
            n += 1
    print(f"OCI CRUD r3: {n} → {path}")
    return n

# ── IBM ──────────────────────────────────────────────────────────────────────
def gen_ibm(out_dir):
    path = os.path.join(out_dir, "ciem_ibm_crud_r3.sql")
    n = 0
    rules = [
        # Power Virtual Server
        ("power_iaas","instance.create","Create Power Virtual Server Instance","Power VS Instances"),
        ("power_iaas","instance.update","Update Power Virtual Server Instance","Power VS Instances"),
        ("power_iaas","instance.delete","Delete Power Virtual Server Instance","Power VS Instances"),
        ("power_iaas","instance.start","Start Power Virtual Server Instance","Power VS Instances"),
        ("power_iaas","instance.stop","Stop Power Virtual Server Instance","Power VS Instances"),
        ("power_iaas","volume.create","Create Power VS Volume","Power VS Volumes"),
        ("power_iaas","volume.delete","Delete Power VS Volume","Power VS Volumes"),
        ("power_iaas","network.create","Create Power VS Network","Power VS Networks"),
        ("power_iaas","ssh-key.create","Create Power VS SSH Key","Power VS SSH Keys"),
        ("power_iaas","image.create","Create Power VS Custom Image","Power VS Images"),
        # VMware Solutions
        ("vmwaresolutions","instance.create","Create VMware Solutions Instance","VMware Instances"),
        ("vmwaresolutions","instance.update","Update VMware Solutions Instance","VMware Instances"),
        ("vmwaresolutions","instance.delete","Delete VMware Solutions Instance","VMware Instances"),
        ("vmwaresolutions","cluster.create","Create VMware Cluster","VMware Clusters"),
        ("vmwaresolutions","cluster.delete","Delete VMware Cluster","VMware Clusters"),
        # Watson AI Services
        ("watson_assistant","environment.create","Create Watson Assistant Environment","WA Environments"),
        ("watson_assistant","environment.delete","Delete Watson Assistant Environment","WA Environments"),
        ("watson_assistant","skill.create","Create Watson Assistant Skill","WA Skills"),
        ("watson_discovery","project.create","Create Watson Discovery Project","WD Projects"),
        ("watson_discovery","project.delete","Delete Watson Discovery Project","WD Projects"),
        ("watson_discovery","collection.create","Create Watson Discovery Collection","WD Collections"),
        ("natural_language_understanding","instance.create","Create NLU Instance","NLU Instances"),
        # Watsonx
        ("watsonx_ai","space.create","Create Watsonx.ai Space","Watsonx Spaces"),
        ("watsonx_ai","space.delete","Delete Watsonx.ai Space","Watsonx Spaces"),
        ("watsonx_ai","deployment.create","Create Watsonx Model Deployment","Watsonx Deployments"),
        ("watsonx_ai","deployment.delete","Delete Watsonx Model Deployment","Watsonx Deployments"),
        ("watsonx_data","instance.create","Create Watsonx.data Instance","Watsonx Data Instances"),
        # IKS / ROKS more ops
        ("containers_kubernetes","zone.add","Add Zone to Worker Pool","IKS Zones"),
        ("containers_kubernetes","zone.remove","Remove Zone from Worker Pool","IKS Zones"),
        ("containers_kubernetes","policy.set","Set IKS Security Policy","IKS Policies"),
        ("containers_kubernetes","addon.enable","Enable IKS Cluster Addon","IKS Addons"),
        ("containers_kubernetes","addon.disable","Disable IKS Cluster Addon","IKS Addons"),
        ("containers_kubernetes","apikey.reset","Reset IKS API Key","IKS API Keys"),
        # Container Registry more
        ("container_registry","image.restore","Restore Container Image","Registry Images"),
        ("container_registry","quota.set","Set Registry Quota","Registry Quotas"),
        ("container_registry","token.create","Create Registry Token","Registry Tokens"),
        ("container_registry","token.delete","Delete Registry Token","Registry Tokens"),
        # VPC more ops
        ("is","vpn-gateway.create","Create VPN Gateway","VPC VPN Gateways"),
        ("is","vpn-gateway.delete","Delete VPN Gateway","VPC VPN Gateways"),
        ("is","vpn-connection.create","Create VPN Connection","VPC VPN Connections"),
        ("is","vpn-connection.delete","Delete VPN Connection","VPC VPN Connections"),
        ("is","endpoint-gateway.create","Create VPC Endpoint Gateway","VPC Endpoint Gateways"),
        ("is","endpoint-gateway.delete","Delete VPC Endpoint Gateway","VPC Endpoint Gateways"),
        ("is","flow-log-collector.create","Create Flow Log Collector","VPC Flow Logs"),
        ("is","flow-log-collector.delete","Delete Flow Log Collector","VPC Flow Logs"),
        ("is","share.create","Create File Share","VPC File Shares"),
        ("is","share.delete","Delete File Share","VPC File Shares"),
        ("is","placement-group.create","Create Instance Placement Group","VPC Placement Groups"),
        ("is","bare-metal-server.create","Create Bare Metal Server","VPC Bare Metal Servers"),
        ("is","bare-metal-server.delete","Delete Bare Metal Server","VPC Bare Metal Servers"),
        # Transit Gateway more
        ("transit_gateway","prefix-filter.create","Create TGW Prefix Filter","TGW Prefix Filters"),
        ("transit_gateway","prefix-filter.delete","Delete TGW Prefix Filter","TGW Prefix Filters"),
        ("transit_gateway","route-report.create","Create TGW Route Report","TGW Route Reports"),
        # DNS Services more
        ("dns_svcs","custom-resolver.create","Create Custom DNS Resolver","DNS Custom Resolvers"),
        ("dns_svcs","custom-resolver.delete","Delete Custom DNS Resolver","DNS Custom Resolvers"),
        ("dns_svcs","custom-resolver.update","Update Custom DNS Resolver","DNS Custom Resolvers"),
        # Security Groups more
        ("is","security-group-rule.create","Create Security Group Rule","VPC SG Rules"),
        ("is","security-group-rule.delete","Delete Security Group Rule","VPC SG Rules"),
        # Event Notifications more
        ("event_notifications","destination.create","Create EN Destination","EN Destinations"),
        ("event_notifications","destination.delete","Delete EN Destination","EN Destinations"),
        ("event_notifications","source.create","Create EN Source","EN Sources"),
        # App ID more
        ("appid","user.create","Create App ID Cloud Directory User","App ID Users"),
        ("appid","user.delete","Delete App ID Cloud Directory User","App ID Users"),
        ("appid","role.create","Create App ID Role","App ID Roles"),
        ("appid","role.delete","Delete App ID Role","App ID Roles"),
        # Schematics more
        ("schematics","blueprint.create","Create Schematics Blueprint","Schematics Blueprints"),
        ("schematics","blueprint.delete","Delete Schematics Blueprint","Schematics Blueprints"),
        ("schematics","blueprint.apply","Apply Schematics Blueprint","Schematics Blueprints"),
        # COS more
        ("cloud_object_storage","bucket-notification.create","Create COS Bucket Notification","COS Notifications"),
        ("cloud_object_storage","bucket-key.set","Set COS Bucket Encryption Key","COS Encryption"),
        ("cloud_object_storage","bucket-website.set","Set COS Bucket Static Website","COS Static Web"),
        # Secrets Manager more
        ("secrets_manager","secret-version.create","Create Secret Version","SM Secret Versions"),
        ("secrets_manager","engine.set","Set Secrets Manager Engine Config","SM Engine Config"),
        # Monitoring more
        ("sysdig_monitor","dashboard.create","Create Monitoring Dashboard","Monitoring Dashboards"),
        ("sysdig_monitor","dashboard.delete","Delete Monitoring Dashboard","Monitoring Dashboards"),
        ("sysdig_monitor","scope.create","Create Monitoring Scope","Monitoring Scopes"),
        ("sysdig_monitor","scope.delete","Delete Monitoring Scope","Monitoring Scopes"),
        # Toolchain / CD more
        ("continuous_delivery","tekton-pipeline-trigger.create","Create Tekton Pipeline Trigger","Tekton Triggers"),
        ("continuous_delivery","tekton-pipeline-trigger.delete","Delete Tekton Pipeline Trigger","Tekton Triggers"),
        ("toolchain","integration.create","Create Toolchain Integration","Toolchain Integrations"),
        ("toolchain","integration.delete","Delete Toolchain Integration","Toolchain Integrations"),
        # LogDNA more
        ("logdna","view.create","Create Log Analysis View","Log Analysis Views"),
        ("logdna","view.delete","Delete Log Analysis View","Log Analysis Views"),
        ("logdna","alert.create","Create Log Analysis Alert","Log Analysis Alerts"),
        ("logdna","alert.delete","Delete Log Analysis Alert","Log Analysis Alerts"),
        # ATracker more
        ("atracker","settings.update","Update Activity Tracker Settings","ATracker Settings"),
        # CBR more
        ("context_based_restrictions","account-settings.update","Update Account CBR Settings","CBR Account Settings"),
        # Functions more
        ("functions","package.create","Create Functions Package","Functions Packages"),
        ("functions","package.delete","Delete Functions Package","Functions Packages"),
        ("functions","trigger.fire","Fire Function Trigger","Functions Trigger Fires"),
    ]
    with open(path, "w") as f:
        f.write("-- IBM CRUD round 3\n")
        for svc, verb, display, res in rules:
            cat = infer_cat(verb + " " + display)
            rid = f"log.ibm.{svc}.{hashlib.md5((svc+verb).encode()).hexdigest()[:8]}"
            title = f"IBM {res}: {display}"
            emit(f, rid, svc, "ibm", title, f"Detected {verb} on {res} via IBM Activity Tracker.", cat, cfg_ibm(svc, verb), verb)
            n += 1
    print(f"IBM CRUD r3: {n} → {path}")
    return n

if __name__ == "__main__":
    gcp = gen_gcp(OUT_DIR)
    oci = gen_oci(OUT_DIR)
    ibm = gen_ibm(OUT_DIR)
    print(f"\nTotal: {gcp+oci+ibm}")
    print(f"Expected after insert: GCP={424+gcp}, OCI={390+oci}, IBM={388+ibm}")
