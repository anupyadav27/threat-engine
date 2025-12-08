#!/usr/bin/env python3
"""Test IBM Cloud credentials and connectivity"""
import os
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_platform_services import IamPolicyManagementV1, IamAccessGroupsV2

def test_ibm_credentials(api_key, account_id, region="us-south"):
    """Test IBM Cloud credentials and basic connectivity"""
    
    print(f"🧪 Testing IBM Cloud Credentials")
    print(f"Account ID: {account_id[:8]}...")
    print(f"API Key: {api_key[:8]}...")
    print(f"Region: {region}")
    print()
    
    try:
        # Test IAM Authentication
        authenticator = IAMAuthenticator(api_key)
        
        # Test Policy Management Service
        print("📋 Testing IAM Policy Management...")
        policy_service = IamPolicyManagementV1(authenticator=authenticator)
        policy_service.set_default_headers({'X-Correlation-ID': 'threat-engine-test'})
        
        # List first few policies
        policies_response = policy_service.list_policies(account_id=account_id, limit=5)
        policies = policies_response.get_result()
        print(f"✅ Found {len(policies.get('policies', []))} policies")
        
        # Test Access Groups Service  
        print("👥 Testing IAM Access Groups...")
        access_groups_service = IamAccessGroupsV2(authenticator=authenticator)
        access_groups_service.set_default_headers({'X-Correlation-ID': 'threat-engine-test'})
        
        groups_response = access_groups_service.list_access_groups(account_id=account_id, limit=5)
        groups = groups_response.get_result()
        print(f"✅ Found {len(groups.get('groups', []))} access groups")
        
        print()
        print("🎉 IBM Cloud credentials are WORKING!")
        print("🚀 Ready to run compliance engine against your IBM account!")
        return True
        
    except Exception as e:
        print(f"❌ Credential test failed: {e}")
        print()
        print("💡 Common issues:")
        print("   • Check API key is correct and not expired")
        print("   • Verify account ID is accurate") 
        print("   • Ensure your account has IAM permissions")
        print("   • Check if services are enabled in your account")
        return False

if __name__ == '__main__':
    # Get credentials from environment variables
    API_KEY = os.getenv('IBM_API_KEY')
    ACCOUNT_ID = os.getenv('IBM_ACCOUNT_ID') 
    REGION = os.getenv('IBM_REGION', 'us-south')
    
    if not API_KEY or not ACCOUNT_ID:
        print("❌ Missing IBM credentials!")
        print()
        print("🔧 Set environment variables:")
        print("   export IBM_API_KEY='your-api-key-here'")
        print("   export IBM_ACCOUNT_ID='your-account-id-here'")
        print("   export IBM_REGION='us-south'  # optional")
        print()
        print("Then run: python3 test_ibm_credentials.py")
        exit(1)
    
    test_ibm_credentials(API_KEY, ACCOUNT_ID, REGION)