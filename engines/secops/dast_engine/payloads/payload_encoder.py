"""
Payload Encoder - Generates encoded and obfuscated payload variants
Helps bypass WAFs, filters, and other security controls
"""

import urllib.parse
import base64
import html
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)


class PayloadEncoder:
    """
    Encodes payloads in various formats to bypass filters
    
    Encoding types:
    - URL encoding (single and double)
    - Unicode encoding
    - HTML entity encoding
    - Base64 encoding
    - Case variations
    - Null byte injection
    """
    
    @staticmethod
    def url_encode(payload: str, double: bool = False) -> str:
        """
        URL encode the payload
        
        Args:
            payload: Original payload
            double: Apply double URL encoding
            
        Returns:
            URL encoded payload
            
        Example:
            >>> encoder = PayloadEncoder()
            >>> encoder.url_encode("<script>alert(1)</script>")
            '%3Cscript%3Ealert%281%29%3C%2Fscript%3E'
        """
        encoded = urllib.parse.quote(payload, safe='')
        
        if double:
            encoded = urllib.parse.quote(encoded, safe='')
        
        return encoded
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """
        Unicode encode the payload
        
        Args:
            payload: Original payload
            
        Returns:
            Unicode encoded payload
            
        Example:
            >>> encoder = PayloadEncoder()
            >>> encoder.unicode_encode("<script>")
            '\\u003cscript\\u003e'
        """
        return payload.encode('unicode-escape').decode('ascii')
    
    @staticmethod
    def html_entity_encode(payload: str, use_hex: bool = False) -> str:
        """
        HTML entity encode the payload
        
        Args:
            payload: Original payload
            use_hex: Use hex entities instead of decimal
            
        Returns:
            HTML entity encoded payload
            
        Example:
            >>> encoder = PayloadEncoder()
            >>> encoder.html_entity_encode("<script>")
            '&lt;script&gt;'
        """
        if use_hex:
            # Hex entity encoding
            return ''.join(f'&#x{ord(c):x};' for c in payload)
        else:
            # HTML escape
            return html.escape(payload)
    
    @staticmethod
    def html_entity_encode_decimal(payload: str) -> str:
        """
        HTML entity encode using decimal entities
        
        Args:
            payload: Original payload
            
        Returns:
            Decimal HTML entity encoded payload
            
        Example:
            >>> encoder = PayloadEncoder()
            >>> encoder.html_entity_encode_decimal("<script>")
            '&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;'
        """
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """
        Base64 encode the payload
        
        Args:
            payload: Original payload
            
        Returns:
            Base64 encoded payload
        """
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def case_variants(payload: str) -> List[str]:
        """
        Generate case variations of the payload
        
        Args:
            payload: Original payload
            
        Returns:
            List of case variants
            
        Example:
            >>> encoder = PayloadEncoder()
            >>> encoder.case_variants("<script>")
            ['<SCRIPT>', '<ScRiPt>', '<sCrIpT>']
        """
        variants = [
            payload.upper(),
            payload.lower(),
        ]
        
        # Alternate case (sCrIpT)
        alternate = ''.join(
            c.upper() if i % 2 == 0 else c.lower() 
            for i, c in enumerate(payload)
        )
        variants.append(alternate)
        
        # Reverse alternate (ScRiPt)
        reverse_alternate = ''.join(
            c.lower() if i % 2 == 0 else c.upper() 
            for i, c in enumerate(payload)
        )
        variants.append(reverse_alternate)
        
        return list(set(variants))  # Remove duplicates
    
    @staticmethod
    def add_null_byte(payload: str) -> str:
        """
        Add null byte to payload (for older systems)
        
        Args:
            payload: Original payload
            
        Returns:
            Payload with null byte appended
        """
        return payload + '%00'
    
    @staticmethod
    def mixed_encoding(payload: str) -> str:
        """
        Mix different encoding types
        
        Args:
            payload: Original payload
            
        Returns:
            Mixed encoded payload
        """
        # Example: URL encode special chars, leave alphanumeric
        result = []
        for c in payload:
            if c.isalnum():
                result.append(c)
            else:
                result.append(urllib.parse.quote(c))
        
        return ''.join(result)
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """
        Hex encode the payload
        
        Args:
            payload: Original payload
            
        Returns:
            Hex encoded payload (0x format)
        """
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    @staticmethod
    def octal_encode(payload: str) -> str:
        """
        Octal encode the payload
        
        Args:
            payload: Original payload
            
        Returns:
            Octal encoded payload
        """
        return ''.join(f'\\{ord(c):03o}' for c in payload)
    
    def get_all_variants(self, payload: str, max_variants: int = 10) -> List[str]:
        """
        Generate multiple encoded variants of a payload
        
        Args:
            payload: Original payload
            max_variants: Maximum number of variants to generate
            
        Returns:
            List of encoded payload variants
            
        Example:
            >>> encoder = PayloadEncoder()
            >>> variants = encoder.get_all_variants("' OR 1=1--")
            >>> len(variants)
            10
        """
        variants = [payload]  # Include original
        
        try:
            # Add basic encodings
            variants.append(self.url_encode(payload))
            variants.append(self.url_encode(payload, double=True))
            variants.append(self.unicode_encode(payload))
            variants.append(self.html_entity_encode(payload))
            variants.append(self.html_entity_encode_decimal(payload))
            variants.append(self.base64_encode(payload))
            variants.append(self.hex_encode(payload))
            
            # Add case variants for payloads with letters
            if any(c.isalpha() for c in payload):
                case_vars = self.case_variants(payload)
                variants.extend(case_vars[:3])  # Add first 3 case variants
            
            # Add null byte variant
            variants.append(self.add_null_byte(payload))
            
        except Exception as e:
            logger.warning(f"Error generating variants for payload: {e}")
        
        # Remove duplicates and limit
        unique_variants = list(dict.fromkeys(variants))
        
        return unique_variants[:max_variants]
    
    @staticmethod
    def encode_for_context(payload: str, context: str) -> str:
        """
        Encode payload based on injection context
        
        Args:
            payload: Original payload
            context: Injection context (url, html, js, sql, etc.)
            
        Returns:
            Context-appropriate encoded payload
        """
        encoder = PayloadEncoder()
        
        context = context.lower()
        
        if context == 'url':
            return encoder.url_encode(payload)
        elif context == 'html':
            return encoder.html_entity_encode(payload)
        elif context == 'js' or context == 'javascript':
            return encoder.unicode_encode(payload)
        elif context == 'base64':
            return encoder.base64_encode(payload)
        elif context == 'hex':
            return encoder.hex_encode(payload)
        else:
            return payload
    
    def generate_bypass_variants(self, payload: str, filter_type: str = 'generic') -> List[str]:
        """
        Generate variants specifically for bypassing filters
        
        Args:
            payload: Original payload
            filter_type: Type of filter to bypass (waf, generic, etc.)
            
        Returns:
            List of bypass variants
        """
        variants = [payload]
        
        if filter_type == 'waf' or filter_type == 'generic':
            # Common WAF bypass techniques
            variants.append(self.url_encode(payload))
            variants.append(self.url_encode(payload, double=True))
            variants.extend(self.case_variants(payload)[:2])
            variants.append(self.add_null_byte(payload))
            variants.append(self.mixed_encoding(payload))
        
        return list(dict.fromkeys(variants))  # Remove duplicates


# Create module-level instance for convenience
encoder = PayloadEncoder()


# Convenience functions
def url_encode(payload: str, double: bool = False) -> str:
    """Convenience function for URL encoding"""
    return encoder.url_encode(payload, double)


def get_encoded_variants(payload: str, max_variants: int = 10) -> List[str]:
    """Convenience function to get all variants"""
    return encoder.get_all_variants(payload, max_variants)
