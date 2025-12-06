step1: from rule to metadata file and check file.. structure 
sorry let do it better way .. we have a services folder /Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services.. for all service in rule_id.yaml, create a folder , inside the folder create two subfolder metadata and checks . under etdata create sepearte yaml file for each rule_id asssociated with that service. in each rule_id metadata file will keep all yield of that rule_id.yaml and yaml file will be same as rule_id name .. the check name will be service_checks.yaml .. the conetnt of check will be decided in next phase 


Step 2:populate the checks file 

 now that we have the folder structure we neeed 


 Quality validaton - checks fro all rule_id . so rule_id =metadata files = check for each metadata 

Step 3:
 before remove the checks folder from each services so that we have clean structure .. after taht let's review the fles and plan if we can ceate the mapping for each rules's fields need to check--->require function of services ot get that fields and -->services /resource discovery functions , this will help use to validate all rules with less chance of error , right ?


 Step 4: 

 : Boto3 Schema Validation & Auto-Fix
I'll create a tool that:
Extracts Boto3 service schemas
Validates our API calls against real Boto3 methods
Maps response structures to fix field names
Auto-generates corrected discovery steps
Updates all service files
Let me start building:


but we decided to validate the boto3 Boto3 Schema Validation & Auto-Fix, shouldn't we just run the bto3 respective command in verbore or any other mode to get verify the all client , fucntion and config value .. i think we should do it for all rule files and inside that all checks and 