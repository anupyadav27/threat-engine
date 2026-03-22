"""
Payload Library for DAST Scanner
Curated payloads categorized by vulnerability type

Based on industry-standard sources:
- SecLists (https://github.com/danielmiessler/SecLists)
- PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
- OWASP Testing Guide
"""

from .payload_loader import PayloadLoader, PayloadCategory
from .payload_encoder import PayloadEncoder

__all__ = ['PayloadLoader', 'PayloadEncoder', 'PayloadCategory']

__version__ = '1.0.0'
