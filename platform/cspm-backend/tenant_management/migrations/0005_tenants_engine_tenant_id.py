from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenant_management', '0004_tenantidpconfig'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenants',
            name='engine_tenant_id',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
    ]
