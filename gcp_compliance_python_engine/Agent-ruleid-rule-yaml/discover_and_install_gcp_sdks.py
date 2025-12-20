#!/usr/bin/env python3
"""
Discover installed GCP SDK packages, install missing ones, and generate catalog.

This script:
1. Discovers all installed google-cloud-* packages
2. Queries PyPI for all available google-cloud-* packages
3. Identifies missing packages
4. Installs missing packages (with user confirmation)
5. Runs service discovery to generate catalog
"""

import json
import subprocess
import sys
import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Try to import pkg_resources (optional)
try:
    import pkg_resources
except ImportError:
    pkg_resources = None

# Try to import pip's package finder (may not be available in all environments)
try:
    from pip._internal.cli.main import main as pip_main
except ImportError:
    try:
        from pip import main as pip_main
    except ImportError:
        pip_main = None


class GCPSDKManager:
    """Manage GCP SDK package discovery and installation"""
    
    def __init__(self):
        self.installed_packages = set()
        self.available_packages = set()
        self.missing_packages = set()
        
    def discover_installed_packages(self) -> Set[str]:
        """Discover all installed google-cloud-* packages"""
        print("=" * 80)
        print("Discovering Installed GCP SDK Packages")
        print("=" * 80)
        print()
        
        installed = set()
        
        # Method 1: Check via importlib
        try:
            import google.cloud
            google_cloud_path = google.cloud.__path__
            
            for importer, modname, ispkg in pkgutil.walk_packages(google_cloud_path, 'google.cloud.'):
                if ispkg:
                    parts = modname.split('.')
                    if len(parts) >= 3 and parts[0] == 'google' and parts[1] == 'cloud':
                        service_name = parts[2]
                        if service_name not in ['core', 'common', 'auth', 'exceptions', 'helpers']:
                            installed.add(service_name)
        except ImportError:
            print("  ⚠️  google.cloud not installed")
        
        # Method 2: Check via pkg_resources (pip installed packages)
        if pkg_resources:
            try:
                for dist in pkg_resources.working_set:
                    if dist.project_name.startswith('google-cloud-'):
                        # Extract service name from package name
                        service_name = dist.project_name.replace('google-cloud-', '').replace('-', '_')
                        installed.add(service_name)
            except Exception as e:
                print(f"  ⚠️  Error checking pkg_resources: {e}")
        
        # Method 3: Try to query pip list
        for pip_cmd in [['python3', '-m', 'pip'], ['pip3'], ['pip']]:
            try:
                result = subprocess.run(
                    pip_cmd + ['list', '--format=json'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    packages = json.loads(result.stdout)
                    for pkg in packages:
                        name = pkg['name']
                        if name.startswith('google-cloud-'):
                            service_name = name.replace('google-cloud-', '').replace('-', '_')
                            installed.add(service_name)
                    break  # Success, no need to try other commands
            except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
                continue
            except Exception as e:
                if pip_cmd == ['pip']:  # Only show error for last attempt
                    print(f"  ⚠️  Error querying pip list: {e}")
        
        self.installed_packages = installed
        print(f"  ✅ Found {len(installed)} installed packages")
        if installed:
            print(f"     Packages: {', '.join(sorted(installed)[:20])}")
            if len(installed) > 20:
                print(f"     ... and {len(installed) - 20} more")
        
        return installed
    
    def discover_available_packages(self) -> Set[str]:
        """Discover all available google-cloud-* packages from PyPI"""
        print("\n" + "=" * 80)
        print("Discovering Available GCP SDK Packages from PyPI")
        print("=" * 80)
        print()
        print("  🔍 Querying PyPI (this may take a moment)...")
        
        available = set()
        
        # Method 1: Use pip search (deprecated but might work)
        try:
            result = subprocess.run(
                ['pip', 'search', 'google-cloud-'],
                capture_output=True,
                text=True,
                timeout=60
            )
            # Note: pip search is deprecated, may not work
        except Exception:
            pass
        
        # Method 2: Query PyPI JSON API
        try:
            import urllib.request
            import urllib.error
            
            # Query PyPI for google-cloud packages
            url = "https://pypi.org/search/?q=google-cloud-&c=Programming+Language+%3A%3A+Python"
            
            # Alternative: Use PyPI simple index
            # We'll use a curated list for now and try to verify with PyPI API
            
            # Known GCP SDK packages (curated list)
            known_packages = [
                'google-cloud-storage', 'google-cloud-compute', 'google-cloud-container',
                'google-cloud-bigquery', 'google-cloud-dns', 'google-cloud-iam',
                'google-cloud-kms', 'google-cloud-logging', 'google-cloud-monitoring',
                'google-cloud-resource-manager', 'google-cloud-sql', 'google-cloud-functions',
                'google-cloud-pubsub', 'google-cloud-dataproc', 'google-cloud-dataflow',
                'google-cloud-spanner', 'google-cloud-firestore', 'google-cloud-bigtable',
                'google-cloud-secret-manager', 'google-cloud-asset', 'google-cloud-security-center',
                'google-cloud-recommender', 'google-cloud-service-usage', 'google-cloud-artifact-registry',
                'google-cloud-appengine', 'google-cloud-build', 'google-cloud-endpoints',
                'google-cloud-scheduler', 'google-cloud-tasks', 'google-cloud-workflows',
                'google-cloud-redis', 'google-cloud-memcache', 'google-cloud-service-directory',
                'google-cloud-trace', 'google-cloud-error-reporting', 'google-cloud-profiler',
                'google-cloud-vision', 'google-cloud-language', 'google-cloud-translate',
                'google-cloud-speech', 'google-cloud-texttospeech', 'google-cloud-videointelligence',
                'google-cloud-documentai', 'google-cloud-automl', 'google-cloud-aiplatform',
                'google-cloud-billing', 'google-cloud-org-policy', 'google-cloud-os-config',
                'google-cloud-notebooks', 'google-cloud-datacatalog', 'google-cloud-datastore',
                'google-cloud-dlp', 'google-cloud-healthcare', 'google-cloud-filestore',
                'google-cloud-vpc-access', 'google-cloud-identity', 'google-cloud-access-approval',
                'google-cloud-certificate-manager', 'google-cloud-essential-contacts',
                'google-cloud-backupdr', 'google-cloud-domains', 'google-cloud-api-keys',
                'google-cloud-apigee-registry', 'google-cloud-policy-troubleshooter',
                'google-cloud-web-risk', 'google-cloud-websecurityscanner',
                'google-cloud-resource-manager', 'google-cloud-iam-credentials',
                'google-cloud-recaptcha-enterprise', 'google-cloud-media-translation',
                'google-cloud-datastream', 'google-cloud-memstore', 'google-cloud-netapp',
                'google-cloud-network-connectivity', 'google-cloud-network-security',
                'google-cloud-network-services', 'google-cloud-optimization',
                'google-cloud-orchestration-airflow', 'google-cloud-parallelstore',
                'google-cloud-phishing-protection', 'google-cloud-private-catalog',
                'google-cloud-privileged-access-manager', 'google-cloud-public-ca',
                'google-cloud-pubsublite', 'google-cloud-recommender', 'google-cloud-retail',
                'google-cloud-run', 'google-cloud-scc', 'google-cloud-scheduler',
                'google-cloud-secret-manager', 'google-cloud-security-private-ca',
                'google-cloud-service-control', 'google-cloud-service-directory',
                'google-cloud-service-management', 'google-cloud-service-usage',
                'google-cloud-shell', 'google-cloud-source-context', 'google-cloud-speech',
                'google-cloud-storage-insights', 'google-cloud-storage-transfer',
                'google-cloud-talent', 'google-cloud-tasks', 'google-cloud-texttospeech',
                'google-cloud-tpu', 'google-cloud-trace', 'google-cloud-translate',
                'google-cloud-videointelligence', 'google-cloud-vision',
                'google-cloud-vm-migration', 'google-cloud-vmmigration',
                'google-cloud-vpc-access', 'google-cloud-web-risk',
                'google-cloud-websecurityscanner', 'google-cloud-workflows',
                'google-cloud-workstations', 'google-cloud-wrapper'
            ]
            
            # Extract service names from package names
            for pkg_name in known_packages:
                # Convert google-cloud-service-name to service_name
                service_name = pkg_name.replace('google-cloud-', '').replace('-', '_')
                available.add(service_name)
                
                # Also try variations
                if '-' in service_name:
                    # Some services might use hyphens
                    available.add(service_name.replace('_', '-'))
            
            print(f"  ✅ Found {len(available)} available packages (from curated list)")
            
            # Try to verify some packages exist via PyPI JSON API
            verified_count = 0
            for pkg_name in list(known_packages)[:10]:  # Test first 10
                try:
                    api_url = f"https://pypi.org/pypi/{pkg_name}/json"
                    with urllib.request.urlopen(api_url, timeout=5) as response:
                        if response.status == 200:
                            verified_count += 1
                except Exception:
                    pass
            
            if verified_count > 0:
                print(f"  ✅ Verified {verified_count} packages exist on PyPI")
        
        except Exception as e:
            print(f"  ⚠️  Error querying PyPI: {e}")
            print(f"  📋 Using curated list of known packages")
        
        self.available_packages = available
        return available
    
    def identify_missing_packages(self) -> Set[str]:
        """Identify packages that are available but not installed"""
        missing = self.available_packages - self.installed_packages
        self.missing_packages = missing
        return missing
    
    def install_packages(self, packages: List[str], interactive: bool = True) -> Dict[str, bool]:
        """Install GCP SDK packages"""
        print("\n" + "=" * 80)
        print("Installing Missing GCP SDK Packages")
        print("=" * 80)
        print()
        
        if not packages:
            print("  ✅ No packages to install")
            return {}
        
        # Convert service names back to package names
        package_names = []
        for service_name in packages:
            # Convert service_name back to google-cloud-service-name
            pkg_name = f"google-cloud-{service_name.replace('_', '-')}"
            package_names.append(pkg_name)
        
        print(f"  📦 Packages to install: {len(package_names)}")
        print(f"     {', '.join(package_names[:10])}")
        if len(package_names) > 10:
            print(f"     ... and {len(package_names) - 10} more")
        
        if interactive:
            response = input("\n  ❓ Install these packages? (y/n): ").strip().lower()
            if response != 'y':
                print("  ⏭️  Skipping installation")
                return {}
        
        results = {}
        
        # Install packages in batches to avoid overwhelming
        batch_size = 5
        for i in range(0, len(package_names), batch_size):
            batch = package_names[i:i+batch_size]
            print(f"\n  📥 Installing batch {i//batch_size + 1}/{(len(package_names)-1)//batch_size + 1}...")
            
            for pkg_name in batch:
                try:
                    print(f"     Installing {pkg_name}...", end=' ', flush=True)
                    result = subprocess.run(
                        [sys.executable, '-m', 'pip', 'install', pkg_name, '--quiet'],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    
                    if result.returncode == 0:
                        print("✅")
                        results[pkg_name] = True
                    else:
                        print("❌")
                        results[pkg_name] = False
                        print(f"        Error: {result.stderr[:100]}")
                
                except subprocess.TimeoutExpired:
                    print("⏱️  (timeout)")
                    results[pkg_name] = False
                except Exception as e:
                    print(f"❌ ({e})")
                    results[pkg_name] = False
        
        successful = sum(1 for v in results.values() if v)
        print(f"\n  ✅ Successfully installed: {successful}/{len(package_names)}")
        
        return results
    
    def run_discovery(self):
        """Run the GCP service discovery script"""
        print("\n" + "=" * 80)
        print("Running GCP Service Discovery")
        print("=" * 80)
        print()
        
        discovery_script = Path(__file__).parent / 'discover_and_generate_all_gcp_services.py'
        
        if not discovery_script.exists():
            print(f"  ❌ Discovery script not found: {discovery_script}")
            return False
        
        try:
            result = subprocess.run(
                [sys.executable, str(discovery_script)],
                cwd=discovery_script.parent
            )
            
            return result.returncode == 0
        
        except Exception as e:
            print(f"  ❌ Error running discovery: {e}")
            return False


def main():
    """Main execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Discover and install GCP SDK packages')
    parser.add_argument('--install-all', action='store_true', help='Install all missing packages automatically')
    parser.add_argument('--install-common', action='store_true', help='Install common packages only')
    parser.add_argument('--no-install', action='store_true', help='Skip installation, only discover')
    parser.add_argument('--run-discovery', action='store_true', help='Run service discovery after installation')
    parser.add_argument('--non-interactive', action='store_true', help='Non-interactive mode (use with --install-all)')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("GCP SDK Package Discovery and Installation")
    print("=" * 80)
    print()
    
    manager = GCPSDKManager()
    
    # Step 1: Discover installed packages
    installed = manager.discover_installed_packages()
    
    # Step 2: Discover available packages
    available = manager.discover_available_packages()
    
    # Step 3: Identify missing packages
    missing = manager.identify_missing_packages()
    
    print("\n" + "=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"  Installed packages: {len(installed)}")
    print(f"  Available packages: {len(available)}")
    print(f"  Missing packages: {len(missing)}")
    
    # Common packages (subset)
    common_packages = [
        'storage', 'compute', 'container', 'bigquery', 'dns', 'iam', 'kms',
        'logging', 'monitoring', 'resource_manager', 'sql', 'functions',
        'pubsub', 'dataproc', 'dataflow', 'spanner', 'firestore', 'bigtable',
        'secret_manager', 'asset', 'security_center', 'recommender',
        'service_usage', 'artifact_registry', 'appengine'
    ]
    
    if missing and not args.no_install:
        if args.install_all:
            print(f"\n  📦 Installing all {len(missing)} missing packages...")
            manager.install_packages(sorted(missing), interactive=False)
        elif args.install_common:
            common_missing = [p for p in common_packages if p in missing]
            print(f"\n  📦 Installing {len(common_missing)} common packages...")
            manager.install_packages(common_missing, interactive=False)
        elif not args.non_interactive:
            print(f"\n  Missing: {', '.join(sorted(missing)[:20])}")
            if len(missing) > 20:
                print(f"     ... and {len(missing) - 20} more")
            
            try:
                install_all = input("\n  ❓ Install all missing packages? (y/n/c=common only/a=ask for each): ").strip().lower()
                
                if install_all == 'y':
                    manager.install_packages(sorted(missing), interactive=False)
                elif install_all == 'c':
                    common_missing = [p for p in common_packages if p in missing]
                    manager.install_packages(common_missing, interactive=False)
                elif install_all == 'a':
                    missing_list = sorted(missing)
                    for service_name in missing_list[:10]:  # Limit to first 10
                        response = input(f"  Install google-cloud-{service_name.replace('_', '-')}? (y/n/q=quit): ").strip().lower()
                        if response == 'q':
                            break
                        elif response == 'y':
                            manager.install_packages([service_name], interactive=False)
            except EOFError:
                print("\n  ⚠️  Non-interactive mode - skipping installation")
                print("     Use --install-all or --install-common for automatic installation")
    
    # Step 4: Run discovery
    if args.run_discovery or (not args.non_interactive and not args.no_install):
        print("\n" + "=" * 80)
        if args.run_discovery:
            print("Running service discovery...")
            manager.run_discovery()
        elif not args.non_interactive:
            try:
                run_discovery = input("  ❓ Run service discovery now? (y/n): ").strip().lower()
                if run_discovery == 'y':
                    manager.run_discovery()
            except EOFError:
                print("\n  ⏭️  Skipping discovery (non-interactive)")
    
    print("\n" + "=" * 80)
    print("✅ Complete!")
    print("=" * 80)


if __name__ == '__main__':
    main()

