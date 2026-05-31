from api_security_engine.providers.base import BaseAPISecProvider


def get_provider(csp_name: str) -> BaseAPISecProvider:
    name = csp_name.lower()
    if name == "aws":
        from api_security_engine.providers.aws import AWSAPISecProvider
        return AWSAPISecProvider()
    if name == "azure":
        from api_security_engine.providers.azure import AzureAPISecProvider
        return AzureAPISecProvider()
    if name == "gcp":
        from api_security_engine.providers.gcp import GCPAPISecProvider
        return GCPAPISecProvider()
    if name in ("oci", "oracle"):
        from api_security_engine.providers.oci import OCIAPISecProvider
        return OCIAPISecProvider()
    if name in ("alicloud", "aliyun"):
        from api_security_engine.providers.alicloud import AliCloudAPISecProvider
        return AliCloudAPISecProvider()
    if name in ("k8s", "kubernetes"):
        from api_security_engine.providers.k8s import K8sAPISecProvider
        return K8sAPISecProvider()
    raise ValueError(f"Unsupported CSP for API Security engine: {csp_name}")
