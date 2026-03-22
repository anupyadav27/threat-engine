from typing import Any

class GCPClient:
    def create_bucket(self, **kwargs: Any) -> None:
        pass

# Initialize client
gcp_client = GCPClient()

def test_cloud_access():
    """Test various cloud access configurations"""
    
    # Noncompliant: Public access enabled
    gcp_client.create_bucket(
        name='public-bucket',
        access_control='Public_Read'  # This should trigger the rule
    )

    # Compliant: Private access
    gcp_client.create_bucket(
        name='private-bucket',
        access_control='Private'
    )

    # Compliant: Authenticated access
    gcp_client.create_bucket(
        name='auth-bucket',
        access_control='Authenticated_Read'
    )

if __name__ == '__main__':
    test_cloud_access()
