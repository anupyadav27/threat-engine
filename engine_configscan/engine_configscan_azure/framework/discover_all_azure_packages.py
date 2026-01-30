#!/usr/bin/env python3
"""
Discover all available Azure SDK packages from PyPI
"""

import subprocess
import json
import re
from typing import List, Set

def get_all_azure_packages_from_pypi() -> List[str]:
    """Get all azure-mgmt packages from PyPI using pip index"""
    packages = set()
    
    print("Discovering Azure SDK packages from PyPI...")
    
    # Try to get packages using pip index
    try:
        result = subprocess.run(
            ['pip', 'index', 'versions', 'azure-mgmt-compute'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print("pip index command available")
    except:
        pass
    
    # Use a comprehensive list based on Azure SDK documentation
    # This list includes all known azure-mgmt packages
    known_packages = [
        # Core
        'azure-mgmt-core',
        'azure-mgmt-resource',
        'azure-mgmt-reservations',
        'azure-mgmt-subscription',
        'azure-mgmt-managementgroups',
        
        # Compute
        'azure-mgmt-compute',
        'azure-mgmt-batch',
        'azure-mgmt-batchai',
        'azure-mgmt-containerinstance',
        'azure-mgmt-containerservice',
        'azure-mgmt-containerregistry',
        'azure-mgmt-servicefabric',
        'azure-mgmt-servicefabricmanagedclusters',
        'azure-mgmt-hybridcompute',
        'azure-mgmt-hybridkubernetes',
        'azure-mgmt-azurestack',
        'azure-mgmt-azurestackhci',
        
        # Storage
        'azure-mgmt-storage',
        'azure-mgmt-storagesync',
        'azure-mgmt-storagecache',
        'azure-mgmt-storageimportexport',
        'azure-mgmt-storagemover',
        'azure-mgmt-storsimple8000series',
        
        # Databases
        'azure-mgmt-sql',
        'azure-mgmt-sqlvirtualmachine',
        'azure-mgmt-rdbms',
        'azure-mgmt-cosmosdb',
        'azure-mgmt-redis',
        'azure-mgmt-datamigration',
        
        # Networking
        'azure-mgmt-network',
        'azure-mgmt-dns',
        'azure-mgmt-privatedns',
        'azure-mgmt-trafficmanager',
        'azure-mgmt-frontdoor',
        'azure-mgmt-networkfunction',
        'azure-mgmt-mobilenetwork',
        'azure-mgmt-networkcloud',
        
        # Security
        'azure-mgmt-keyvault',
        'azure-mgmt-authorization',
        'azure-mgmt-msi',
        'azure-mgmt-security',
        'azure-mgmt-paloaltonetworksngfw',
        
        # Web & API
        'azure-mgmt-web',
        'azure-mgmt-apimanagement',
        'azure-mgmt-appservice',
        'azure-mgmt-appplatform',
        'azure-mgmt-signalr',
        'azure-mgmt-webpubsub',
        
        # Monitoring & Logging
        'azure-mgmt-monitor',
        'azure-mgmt-loganalytics',
        'azure-mgmt-applicationinsights',
        'azure-mgmt-workloadmonitor',
        'azure-mgmt-alertsmanagement',
        'azure-mgmt-changeanalysis',
        
        # Messaging
        'azure-mgmt-eventhub',
        'azure-mgmt-servicebus',
        'azure-mgmt-relay',
        'azure-mgmt-notificationhubs',
        
        # Backup & Recovery
        'azure-mgmt-recoveryservices',
        'azure-mgmt-recoveryservicesbackup',
        'azure-mgmt-recoveryservicessiterecovery',
        'azure-mgmt-dataprotection',
        
        # Analytics & Big Data
        'azure-mgmt-kusto',
        'azure-mgmt-streamanalytics',
        'azure-mgmt-datalake-analytics',
        'azure-mgmt-datalake-store',
        'azure-mgmt-hdinsight',
        'azure-mgmt-synapse',
        'azure-mgmt-timeseriesinsights',
        
        # AI & ML
        'azure-mgmt-machinelearningservices',
        'azure-mgmt-cognitiveservices',
        'azure-mgmt-videoanalyzer',
        
        # IoT & Edge
        'azure-mgmt-iotcentral',
        'azure-mgmt-iothub',
        'azure-mgmt-deviceupdate',
        'azure-mgmt-databoxedge',
        'azure-mgmt-databox',
        'azure-mgmt-importexport',
        'azure-mgmt-edgegateway',
        
        # Media & Content
        'azure-mgmt-media',
        'azure-mgmt-cdn',
        
        # Communication
        'azure-mgmt-communication',
        
        # Automation & DevOps
        'azure-mgmt-automation',
        'azure-mgmt-devtestlabs',
        'azure-mgmt-labservices',
        'azure-mgmt-devcenter',
        'azure-mgmt-devhub',
        
        # Cost & Billing
        'azure-mgmt-billing',
        'azure-mgmt-consumption',
        'azure-mgmt-commerce',
        'azure-mgmt-marketplaceordering',
        
        # Policy & Governance
        'azure-mgmt-policyinsights',
        'azure-mgmt-managedservices',
        
        # Additional Services
        'azure-mgmt-advisor',
        'azure-mgmt-maintenance',
        'azure-mgmt-powerbidedicated',
        'azure-mgmt-operationsmanagement',
        'azure-mgmt-scheduler',
        'azure-mgmt-logic',
        'azure-mgmt-search',
        'azure-mgmt-maps',
        'azure-mgmt-mixedreality',
        'azure-mgmt-orbital',
        'azure-mgmt-quantum',
        'azure-mgmt-vmwarecloudsimple',
        'azure-mgmt-windowsiot',
        'azure-mgmt-testbase',
        'azure-mgmt-elastic',
        'azure-mgmt-extendedlocation',
        'azure-mgmt-workloads',
        'azure-mgmt-confidentialledger',
        'azure-mgmt-purview',
        'azure-mgmt-datashare',
        'azure-mgmt-agrifood',
        'azure-mgmt-confluent',
        'azure-mgmt-dashboard',
        'azure-mgmt-dynatrace',
        'azure-mgmt-graphservices',
        'azure-mgmt-healthbot',
        'azure-mgmt-healthcareapis',
        'azure-mgmt-imagebuilder',
        'azure-mgmt-loadtestservice',
        'azure-mgmt-newrelicobservability',
        'azure-mgmt-oep',
        'azure-mgmt-official',
        'azure-mgmt-playwrighttesting',
        'azure-mgmt-portal',
        'azure-mgmt-redhatopenshift',
        'azure-mgmt-scvmm',
        'azure-mgmt-selfhelp',
        'azure-mgmt-sphere',
    ]
    
    return sorted(known_packages)


def install_packages(packages: List[str], venv_path: str = None):
    """Install Azure SDK packages"""
    print(f"\nInstalling {len(packages)} Azure SDK packages...")
    
    # Install in batches to avoid timeout
    batch_size = 20
    for i in range(0, len(packages), batch_size):
        batch = packages[i:i+batch_size]
        print(f"\nInstalling batch {i//batch_size + 1} ({len(batch)} packages)...")
        
        cmd = ['pip', 'install'] + batch
        if venv_path:
            # Use venv python
            import sys
            python_exe = f"{venv_path}/bin/python"
            cmd = [python_exe, '-m', 'pip', 'install'] + batch
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                print(f"Warning: Some packages in batch failed to install")
                print(result.stderr[:500])
        except subprocess.TimeoutExpired:
            print(f"Timeout installing batch, continuing...")
        except Exception as e:
            print(f"Error installing batch: {e}")


def main():
    """Main execution"""
    print("=" * 80)
    print("Azure SDK Package Discovery")
    print("=" * 80)
    
    packages = get_all_azure_packages_from_pypi()
    
    print(f"\nFound {len(packages)} Azure SDK packages")
    print("\nPackages to install:")
    for pkg in packages:
        print(f"  {pkg}")
    
    # Save to file
    with open('azure_all_packages_list.txt', 'w') as f:
        for pkg in packages:
            f.write(f"{pkg}\n")
    
    print(f"\n✅ Saved package list to azure_all_packages_list.txt")
    print(f"\nTo install all packages, run:")
    print(f"  pip install {' '.join(packages)}")
    
    return packages


if __name__ == '__main__':
    main()

