import random
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction
from faker import Faker

from tenant_management.models import Tenants, TenantUsers
from user_auth.models import Roles

User = get_user_model()
fake = Faker()

STATUSES = ["active", "inactive", "suspended", "trial"]
PLANS = ["free", "basic", "pro", "enterprise"]
REGIONS = ["us-east", "us-west", "eu-central", "ap-south"]


class Command(BaseCommand):
    help = "Create random tenants with associated tenant_users"

    def handle(self, *args, **options):
        self.stdout.write("Creating random tenants...")

        if not Roles.objects.exists():
            self.stdout.write("No roles found. Creating default role...")
            Roles.objects.create(name="member", description="Default member role")

        roles = list(Roles.objects.all())

        if not User.objects.filter().exists():
            self.stdout.write("No non-superuser found. Creating test user...")
            User.objects.create_user(
                email="test@example.com",
                password="password123"
            )

        users = list(User.objects.filter(is_superuser=True))
        if not users:
            users = list(User.objects.all())

        if not users or not roles:
            self.stderr.write("Error: Need at least one User and one Role to proceed.")
            return

        tenants_to_create = []
        tenant_users_to_create = []

        num_tenants = 20

        for _ in range(num_tenants):
            tenant = Tenants(
                name=fake.company(),
                description=fake.text(max_nb_chars=200),
                status=random.choice(STATUSES),
                plan=random.choice(PLANS),
                contact_email=fake.email(),
                region=random.choice(REGIONS),
            )
            tenants_to_create.append(tenant)

        Tenants.objects.bulk_create(tenants_to_create)
        self.stdout.write(f"Created {len(tenants_to_create)} tenants.")

        created_tenants = Tenants.objects.all()

        for tenant in created_tenants:
            user = random.choice(users)
            role = random.choice(roles)
            tenant_users_to_create.append(
                TenantUsers(
                    tenant=tenant,
                    user=user,
                    role=role,
                    status=random.choice(STATUSES),
                )
            )

        TenantUsers.objects.bulk_create(tenant_users_to_create)
        self.stdout.write(f"Created {len(tenant_users_to_create)} tenant-user associations.")

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully created {num_tenants} tenants with associated users!"
            )
        )