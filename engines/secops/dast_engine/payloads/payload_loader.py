"""
Payload Loader - Manages loading and accessing security test payloads
Loads curated payloads from organized directory structure
"""

import os
from enum import Enum
from typing import List, Dict, Optional, Set
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class PayloadCategory(Enum):
    """Payload categories matching vulnerability types"""
    SQLI = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SSRF = "ssrf"
    NOSQL = "nosql"
    SSTI = "ssti"
    FUZZING = "fuzzing"


class PayloadLoader:
    """
    Loads and manages security testing payloads from file system
    
    Features:
    - Load payloads by category
    - Load specific subcategories
    - Cache for performance
    - Filter by tags or patterns
    """
    
    def __init__(self, payload_dir: Optional[str] = None):
        """
        Initialize payload loader
        
        Args:
            payload_dir: Path to payload directory (defaults to ./payloads)
        """
        if payload_dir:
            self.payload_dir = Path(payload_dir)
        else:
            # Default to payloads/ directory in project root
            current_file = Path(__file__).resolve()
            self.payload_dir = current_file.parent
        
        self._cache: Dict[str, List[str]] = {}
        self._validate_directory()
    
    def _validate_directory(self):
        """Validate that payload directory exists"""
        if not self.payload_dir.exists():
            logger.warning(f"Payload directory not found: {self.payload_dir}")
            raise FileNotFoundError(f"Payload directory not found: {self.payload_dir}")
    
    def _load_file(self, file_path: Path) -> List[str]:
        """
        Load payloads from a single file
        
        Args:
            file_path: Path to payload file
            
        Returns:
            List of payloads (one per line, comments and empty lines removed)
        """
        payloads = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        payloads.append(line)
            
            logger.debug(f"Loaded {len(payloads)} payloads from {file_path.name}")
            return payloads
            
        except Exception as e:
            logger.error(f"Error loading payload file {file_path}: {e}")
            return []
    
    def load_category(self, category: str) -> List[str]:
        """
        Load all payloads from a category
        
        Args:
            category: Category name (sqli, xss, command_injection, etc.)
            
        Returns:
            List of all payloads in that category
            
        Example:
            >>> loader = PayloadLoader()
            >>> sqli_payloads = loader.load_category('sqli')
            >>> len(sqli_payloads)
            150
        """
        cache_key = f"category:{category}"
        
        # Return from cache if available
        if cache_key in self._cache:
            logger.debug(f"Returning cached payloads for category: {category}")
            return self._cache[cache_key]
        
        category_dir = self.payload_dir / category
        
        if not category_dir.exists():
            logger.warning(f"Category directory not found: {category}")
            return []
        
        payloads = []
        
        # Load all .txt files in category directory
        for file_path in category_dir.glob('*.txt'):
            file_payloads = self._load_file(file_path)
            payloads.extend(file_payloads)
        
        # Cache the results
        self._cache[cache_key] = payloads
        
        logger.info(f"Loaded {len(payloads)} payloads for category: {category}")
        return payloads
    
    def load_payloads(self, category: str, subcategory: Optional[str] = None) -> List[str]:
        """
        Load payloads with optional subcategory filtering
        
        Args:
            category: Category name (sqli, xss, etc.)
            subcategory: Optional subcategory file (error_based, blind, etc.)
            
        Returns:
            List of payloads
            
        Example:
            >>> loader = PayloadLoader()
            >>> # Load all SQLi payloads
            >>> all_sqli = loader.load_payloads('sqli')
            >>> # Load only error-based SQLi
            >>> error_sqli = loader.load_payloads('sqli', 'error_based')
        """
        if subcategory:
            cache_key = f"{category}:{subcategory}"
            
            # Return from cache if available
            if cache_key in self._cache:
                return self._cache[cache_key]
            
            file_path = self.payload_dir / category / f"{subcategory}.txt"
            
            if not file_path.exists():
                logger.warning(f"Subcategory file not found: {file_path}")
                return []
            
            payloads = self._load_file(file_path)
            self._cache[cache_key] = payloads
            
            logger.info(f"Loaded {len(payloads)} payloads for {category}/{subcategory}")
            return payloads
        else:
            return self.load_category(category)
    
    def get_sqli_payloads(self, subcategory: Optional[str] = None) -> List[str]:
        """Get SQL injection payloads"""
        return self.load_payloads('sqli', subcategory)
    
    def get_xss_payloads(self, subcategory: Optional[str] = None) -> List[str]:
        """Get XSS payloads"""
        return self.load_payloads('xss', subcategory)
    
    def get_command_injection_payloads(self, platform: str = 'unix') -> List[str]:
        """
        Get command injection payloads
        
        Args:
            platform: 'unix' or 'windows'
        """
        return self.load_payloads('command_injection', platform)
    
    def get_path_traversal_payloads(self, platform: str = 'unix') -> List[str]:
        """
        Get path traversal payloads
        
        Args:
            platform: 'unix' or 'windows'
        """
        return self.load_payloads('path_traversal', platform)
    
    def get_ssrf_payloads(self, subcategory: Optional[str] = None) -> List[str]:
        """Get SSRF payloads"""
        return self.load_payloads('ssrf', subcategory)
    
    def get_nosql_payloads(self, subcategory: Optional[str] = None) -> List[str]:
        """Get NoSQL injection payloads"""
        return self.load_payloads('nosql', subcategory)
    
    def get_xxe_payloads(self, subcategory: Optional[str] = None) -> List[str]:
        """Get XXE payloads"""
        return self.load_payloads('xxe', subcategory)
    
    def get_ssti_payloads(self, subcategory: Optional[str] = None) -> List[str]:
        """Get SSTI payloads"""
        return self.load_payloads('ssti', subcategory)
    
    def get_fuzzing_payloads(self, subcategory: Optional[str] = None) -> List[str]:
        """Get fuzzing payloads"""
        return self.load_payloads('fuzzing', subcategory)
    
    def get_all_categories(self) -> List[str]:
        """
        Get list of all available payload categories
        
        Returns:
            List of category names
        """
        categories = []
        
        for item in self.payload_dir.iterdir():
            if item.is_dir() and not item.name.startswith('_'):
                categories.append(item.name)
        
        return sorted(categories)
    
    def get_subcategories(self, category: str) -> List[str]:
        """
        Get list of subcategories (files) in a category
        
        Args:
            category: Category name
            
        Returns:
            List of subcategory names (without .txt extension)
        """
        category_dir = self.payload_dir / category
        
        if not category_dir.exists():
            return []
        
        subcategories = []
        
        for file_path in category_dir.glob('*.txt'):
            subcategories.append(file_path.stem)
        
        return sorted(subcategories)
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get payload count statistics
        
        Returns:
            Dictionary mapping category to payload count
        """
        stats = {}
        
        for category in self.get_all_categories():
            payloads = self.load_category(category)
            stats[category] = len(payloads)
        
        return stats
    
    def clear_cache(self):
        """Clear the payload cache"""
        self._cache.clear()
        logger.info("Payload cache cleared")
    
    def add_custom_payload(self, category: str, payload: str, subcategory: str = 'custom'):
        """
        Add a custom payload to a category
        
        Args:
            category: Category name
            payload: The payload string
            subcategory: Subcategory file to add to (default: 'custom')
        """
        # Create category directory if it doesn't exist
        category_dir = self.payload_dir / category
        category_dir.mkdir(exist_ok=True)
        
        # Append to custom file
        custom_file = category_dir / f"{subcategory}.txt"
        
        with open(custom_file, 'a', encoding='utf-8') as f:
            f.write(f"{payload}\n")
        
        # Clear cache for this category
        cache_key = f"category:{category}"
        if cache_key in self._cache:
            del self._cache[cache_key]
        
        cache_key = f"{category}:{subcategory}"
        if cache_key in self._cache:
            del self._cache[cache_key]
        
        logger.info(f"Added custom payload to {category}/{subcategory}")


# Global payload loader instance (singleton pattern)
_global_loader: Optional[PayloadLoader] = None


def get_payload_loader() -> PayloadLoader:
    """
    Get global payload loader instance (singleton)
    
    Returns:
        Global PayloadLoader instance
    """
    global _global_loader
    
    if _global_loader is None:
        _global_loader = PayloadLoader()
    
    return _global_loader
