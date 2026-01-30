# Test script to trigger the cryptographic_key_generation_should_be_based_on_strong_parameters rule
from rsa import newkeys

# This should trigger the rule (weak key size)
key1 = newkeys(64, 64)

# This should NOT trigger the rule (strong key size)
key2 = newkeys(2048, 2048)

# This should also trigger the rule (borderline case)
key3 = newkeys(512, 512)

# This should NOT trigger the rule (exact threshold)
key4 = newkeys(1024, 1024)
