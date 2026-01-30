# Test to trigger unrestricted outbound communications rule
import requests

def test_unrestricted_outbound():
    # Noncompliant: Unvalidated outbound connection
    socket = requests.get("http://example.com")

    # Compliant: Validated outbound connection
    socket = requests.get("http://example.com", verify='my_cert.pem')

if __name__ == "__main__":
    test_unrestricted_outbound()
