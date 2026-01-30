# Test script to trigger 'using_unencrypted_opensearch_domains_is_securitysensitive' rule
import requests

# This should trigger the rule (unencrypted OpenSearch domain)
url = 'https://my-unencrypted-domain.opensearch.org'
response = requests.get(url)

# This should NOT trigger the rule (encrypted domain, but not OpenSearch)
url2 = 'https://secure-domain.example.com'
response2 = requests.get(url2)
