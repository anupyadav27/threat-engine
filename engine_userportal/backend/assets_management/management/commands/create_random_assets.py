# asset_management/management/commands/populate_assets.py
import uuid
import random
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone

from assets_management.models import Asset, AssetTag
from tenant_management.models import Tenants


class Command(BaseCommand):
    help = 'Populates the database with random assets and tags'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=100,
            help='Number of assets to create (default: 100)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Delete existing assets before populating'
        )

    def handle(self, *args, **options):
        count = options['count']
        clear = options['clear']

        # Get all existing tenants
        tenants = list(Tenants.objects.all())
        if not tenants:
            self.stdout.write(
                self.style.ERROR('No tenants found! Create tenants first.')
            )
            return

        # Clear existing data if requested
        if clear:
            Asset.objects.all().delete()
            AssetTag.objects.all().delete()
            self.stdout.write(self.style.SUCCESS('Cleared existing assets and tags'))

        # Generate realistic data pools
        providers = ['aws', 'azure', 'gcp', 'on_prem']
        regions = {
            'aws': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1'],
            'azure': ['eastus', 'westus2', 'northeurope', 'southeastasia'],
            'gcp': ['us-central1', 'us-west1', 'europe-west1', 'asia-south1'],
            'on_prem': ['dc1', 'dc2', 'primary', 'backup']
        }
        environments = ['production', 'staging', 'development', 'test']
        categories = ['compute', 'storage', 'database', 'network', 'security']
        resource_types = {
            'compute': ['ec2_instance', 'vm', 'container', 'lambda'],
            'storage': ['s3_bucket', 'blob_storage', 'file_share', 'ebs_volume'],
            'database': ['rds_instance', 'cosmos_db', 'cloud_sql', 'dynamodb'],
            'network': ['vpc', 'subnet', 'load_balancer', 'firewall'],
            'security': ['iam_role', 'security_group', 'key_vault', 'kms_key']
        }
        lifecycle_states = ['active', 'inactive', 'terminated', 'decommissioned']
        health_statuses = ['healthy', 'warning', 'critical', 'unknown']

        # Common tag keys and values
        tag_keys = ['team', 'cost_center', 'environment', 'owner', 'project', 'compliance']
        tag_values = {
            'team': ['backend', 'frontend', 'devops', 'security', 'data'],
            'cost_center': ['cc-1001', 'cc-1002', 'cc-1003', 'cc-1004'],
            'environment': environments,
            'owner': ['john.doe@company.com', 'jane.smith@company.com', 'dev-team@company.com'],
            'project': ['project-alpha', 'project-beta', 'project-gamma', 'infrastructure'],
            'compliance': ['pci-dss', 'hipaa', 'gdpr', 'sox']
        }

        assets_created = 0
        tags_created = 0

        for i in range(count):
            # Randomly select tenant
            tenant = random.choice(tenants)

            # Generate realistic asset properties
            provider = random.choice(providers)
            region = random.choice(regions[provider])
            environment = random.choice(environments)
            category = random.choice(categories)
            resource_type = random.choice(resource_types[category])

            # Generate realistic names and resource IDs
            name_prefixes = {
                'compute': ['web-server', 'app-server', 'worker', 'api-gateway'],
                'storage': ['data-bucket', 'logs-bucket', 'backup-storage', 'media-store'],
                'database': ['prod-db', 'analytics-db', 'cache-db', 'user-db'],
                'network': ['main-vpc', 'public-subnet', 'alb-prod', 'nat-gateway'],
                'security': ['admin-role', 'web-sg', 'prod-kv', 'encryption-key']
            }

            name = f"{random.choice(name_prefixes.get(category, ['resource']))}-{random.randint(1, 100)}"

            # Generate resource_id based on provider and type
            if provider == 'aws':
                if resource_type == 'ec2_instance':
                    resource_id = f"i-{random.randint(100000000000, 999999999999):012d}"
                elif resource_type == 's3_bucket':
                    resource_id = f"arn:aws:s3:::{name.replace('-', '')}{random.randint(1000, 9999)}"
                else:
                    resource_id = f"arn:aws:{resource_type.replace('_', ':')}:{region}:{random.randint(100000000000, 999999999999)}:{name}"
            elif provider == 'azure':
                resource_id = f"/subscriptions/{str(uuid.uuid4())}/resourceGroups/rg-{environment}/providers/Microsoft.{category.title()}/{resource_type}/{name}"
            elif provider == 'gcp':
                project_id = f"project-{random.randint(1000, 9999)}"
                resource_id = f"//{resource_type.replace('_', '.')}.googleapis.com/projects/{project_id}/zones/{region}/instances/{name}"
            else:  # on_prem
                resource_id = f"server-{name}-{random.randint(100, 999)}"

            # Create asset
            asset = Asset.objects.create(
                id=str(uuid.uuid4()),
                tenant_id=str(tenant.id),
                name=name,
                resource_id=resource_id,
                resource_type=resource_type,
                provider=provider,
                region=region,
                environment=environment,
                category=category,
                lifecycle_state=random.choice(lifecycle_states),
                health_status=random.choice(health_statuses),
                metadata={
                    'created_by': 'populate_assets_script',
                    'source': 'synthetic_data',
                    'version': '1.0'
                },
                created_at=timezone.now() - timedelta(days=random.randint(1, 365)),
                updated_at=timezone.now() - timedelta(hours=random.randint(1, 72))
            )
            assets_created += 1

            # Create 1-5 random tags per asset
            num_tags = random.randint(1, 5)
            used_keys = set()
            for _ in range(num_tags):
                # Ensure unique tag keys per asset
                available_keys = [k for k in tag_keys if k not in used_keys]
                if not available_keys:
                    break

                tag_key = random.choice(available_keys)
                used_keys.add(tag_key)
                tag_value = random.choice(tag_values[tag_key])

                AssetTag.objects.create(
                    id=str(uuid.uuid4()),
                    asset_id=str(asset.id),
                    tag_key=tag_key,
                    tag_value=tag_value,
                    created_at=asset.created_at,
                    updated_at=asset.updated_at
                )
                tags_created += 1

            # Progress indicator
            if (i + 1) % 10 == 0:
                self.stdout.write(f'Created {i + 1}/{count} assets...')

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created {assets_created} assets and {tags_created} tags!'
            )
        )