"""
OCI SDK Compliance Engine

Main engine for executing compliance checks against Oracle Cloud Infrastructure.
"""

import json
import os
import logging
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.reporting_manager import save_reporting_bundle
from auth.oci_auth import OCIAuth
from engine.oci_engine import run_engine

# Setup logging
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, f"compliance_{os.getenv('HOSTNAME', 'local')}.log")
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
logger = logging.getLogger('oci-compliance')
if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
    fh = logging.FileHandler(log_path)
    fh.setLevel(os.getenv('LOG_LEVEL', 'INFO'))
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
    logger.addHandler(fh)


def main():
    """Main entry point for the compliance engine"""
    print("\n" + "="*80)
    print("OCI Compliance Engine")
    print("="*80 + "\n")
    
    # Initialize auth
    try:
        auth = OCIAuth()
        config = auth.get_config()
        
        if not auth.test_connection():
            logger.error("OCI authentication test failed")
            print("❌ OCI authentication failed. Please check your credentials.")
            return
        
        tenancy_id = config.get('tenancy', 'unknown')
        region = config.get('region', 'unknown')
        
        print(f"✅ Authentication successful")
        print(f"   Tenancy: {tenancy_id}")
        print(f"   Region: {region}\n")
        
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        print(f"❌ OCI authentication failed: {e}")
        print("\nPlease ensure:")
        print("  1. OCI CLI is configured (~/.oci/config)")
        print("  2. API key is valid")
        print("  3. User has required permissions")
        return
    
    # Run compliance engine
    try:
        print(f"{'='*80}")
        print(f"Starting Compliance Scan")
        print(f"{'='*80}\n")
        
        all_results = run_engine(config)
        
        # Calculate summary
        total_checks = sum(len(r.get('checks', [])) for r in all_results)
        passed = sum(len([c for c in r.get('checks', []) if c.get('result') == 'PASS']) for r in all_results)
        failed = sum(len([c for c in r.get('checks', []) if c.get('result') == 'FAIL']) for r in all_results)
        
        print(f"\n{'='*80}")
        print(f"Scan Summary")
        print(f"{'='*80}")
        print(f"  Services scanned: {len(all_results)}")
        print(f"  Total checks: {total_checks}")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")
        print(f"{'='*80}\n")
        
    except Exception as e:
        logger.error(f"Compliance scan failed: {e}", exc_info=True)
        print(f"❌ Scan failed: {e}")
        return
    
    # Save results
    try:
        report_folder = save_reporting_bundle(all_results, tenancy_id)
        logger.info(f"Results saved to: {report_folder}")
        
        print(f"✅ Results saved to: {report_folder}\n")
        
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        print(f"⚠️  Warning: Failed to save results: {e}")
    
    return all_results


if __name__ == "__main__":
    main()

