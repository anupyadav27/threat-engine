# This should trigger the rule: hardcoded credentials
username = 'admin'
password = 'password123'
api_key = 'AKIAIOSFODNN7EXAMPLE'

# These should NOT trigger the rule
import os
username = os.environ.get('USERNAME')
password = os.environ.get('PASSWORD')
api_key = os.environ.get('API_KEY')
