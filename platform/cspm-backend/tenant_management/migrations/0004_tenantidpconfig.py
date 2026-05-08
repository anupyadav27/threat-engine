import uuid
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenant_management', '0003_alter_tenants_options_alter_tenantusers_options_and_more'),
        ('user_auth', '0006_invite_and_password_reset_tokens'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='TenantIDPConfig',
            fields=[
                ('id', models.TextField(
                    primary_key=True,
                    default=uuid.uuid4,
                    editable=False,
                    serialize=False,
                )),
                ('idp_type', models.CharField(
                    max_length=20,
                    choices=[
                        ('google_oauth', 'Google OAuth'),
                        ('oidc', 'Generic OIDC'),
                        ('saml', 'SAML 2.0'),
                    ],
                )),
                ('idp_name', models.CharField(max_length=255)),
                ('is_active', models.BooleanField(default=False)),
                ('config', models.JSONField()),
                ('allowed_domains', models.JSONField(default=list)),
                ('tenant', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='idp_configs',
                    to='tenant_management.tenants',
                )),
                ('created_by', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='idp_configs_created',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'db_table': 'tenant_idp_configs'},
        ),
        migrations.AlterUniqueTogether(
            name='tenantidpconfig',
            unique_together={('tenant', 'idp_type', 'idp_name')},
        ),
        migrations.AddIndex(
            model_name='tenantidpconfig',
            index=models.Index(
                fields=['tenant', 'idp_type', 'is_active'],
                name='tenant_idp_type_active_idx',
            ),
        ),
    ]
