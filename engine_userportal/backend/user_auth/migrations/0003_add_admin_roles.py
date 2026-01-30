# Data migration: ensure admin roles exist (super_landlord, landlord, customer_admin, group_admin, tenant)

from django.db import migrations


def create_admin_roles(apps, schema_editor):
    Roles = apps.get_model("user_auth", "Roles")
    names = [
        ("super_landlord", "Platform admin; access all landlords, customers, tenants."),
        ("landlord", "Manages N customers; access those customers and their tenants."),
        ("customer_admin", "One customer; access that customer and all its tenants."),
        ("group_admin", "Multiple customers/tenants; access only those."),
        ("tenant", "Single tenant; access one tenant only."),
    ]
    for name, desc in names:
        if not Roles.objects.filter(name=name).exists():
            Roles.objects.create(name=name, description=desc)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0002_add_user_admin_scope"),
    ]

    operations = [
        migrations.RunPython(create_admin_roles, noop),
    ]
