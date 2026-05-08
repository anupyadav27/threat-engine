import os

from django.core.management.base import BaseCommand

from tenant_management.models import TenantIDPConfig, TenantUsers
from user_auth.models import Users


class Command(BaseCommand):
    help = (
        "Migrate Okta SSO users to per-tenant TenantIDPConfig rows. "
        "Reads OKTA_METADATA, SAML_AUDIENCE, and SAML_CALLBACK_URL env vars. "
        "Idempotent: skips tenants that already have a SAML / Okta (migrated) config."
    )

    def handle(self, *args, **options):
        metadata_url = os.environ.get("OKTA_METADATA", "")
        sp_entity_id = os.environ.get("SAML_AUDIENCE", "")
        acs_url = os.environ.get("SAML_CALLBACK_URL", "")

        if not metadata_url:
            self.stderr.write(
                self.style.WARNING(
                    "OKTA_METADATA env var is not set — continuing with empty value."
                )
            )
        if not sp_entity_id:
            self.stderr.write(
                self.style.WARNING(
                    "SAML_AUDIENCE env var is not set — continuing with empty value."
                )
            )
        if not acs_url:
            self.stderr.write(
                self.style.WARNING(
                    "SAML_CALLBACK_URL env var is not set — continuing with empty value."
                )
            )

        # Find all users whose sso_provider indicates Okta or generic SAML.
        okta_users = Users.objects.filter(
            sso_provider__in=["okta", "saml"]
        )

        user_count = okta_users.count()
        self.stdout.write(
            f"Found {user_count} user(s) with sso_provider in ['okta', 'saml']."
        )

        if user_count == 0:
            self.stdout.write(self.style.SUCCESS("Nothing to migrate."))
            return

        # Collect the unique set of tenants those users belong to.
        tenant_user_links = TenantUsers.objects.filter(
            user__in=okta_users
        ).select_related("tenant").distinct()

        # Deduplicate by tenant id.
        tenants_by_id: dict = {}
        for link in tenant_user_links:
            tenants_by_id[link.tenant.id] = link.tenant

        self.stdout.write(
            f"Identified {len(tenants_by_id)} unique tenant(s) to process."
        )

        idp_config = {
            "entity_id": sp_entity_id,
            "metadata_url": metadata_url,
            "acs_url": acs_url,
            "sp_entity_id": sp_entity_id,
        }

        processed: list[str] = []
        skipped: list[str] = []

        for tenant in tenants_by_id.values():
            already_exists = TenantIDPConfig.objects.filter(
                tenant=tenant,
                idp_type="saml",
                idp_name="Okta (migrated)",
            ).exists()

            if already_exists:
                skipped.append(tenant.name)
                self.stdout.write(
                    self.style.WARNING(
                        f"  SKIP  {tenant.name} (id={tenant.id}) — config already exists."
                    )
                )
                continue

            TenantIDPConfig.objects.create(
                tenant=tenant,
                idp_type="saml",
                idp_name="Okta (migrated)",
                is_active=True,
                config=idp_config,
                allowed_domains=[],
                created_by=None,
            )
            processed.append(tenant.name)
            self.stdout.write(
                self.style.SUCCESS(
                    f"  CREATE {tenant.name} (id={tenant.id}) — TenantIDPConfig created."
                )
            )

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                f"Migration complete. "
                f"Processed: {len(processed)}, Skipped: {len(skipped)}."
            )
        )

        if processed:
            self.stdout.write("  Processed tenants: " + ", ".join(processed))
        if skipped:
            self.stdout.write("  Skipped tenants:   " + ", ".join(skipped))
