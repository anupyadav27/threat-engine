from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('tenant_management', '0005_tenants_engine_tenant_id'),
        ('user_auth', '0010_billing_permissions'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserAccountAccess',
            fields=[
                ('id', models.TextField(primary_key=True, default=uuid.uuid4, editable=False)),
                ('account_id', models.CharField(max_length=512)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('granted_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='account_grants_given',
                    to='user_auth.users',
                )),
                ('tenant', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='account_access',
                    to='tenant_management.tenants',
                )),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='account_access',
                    to='user_auth.users',
                )),
            ],
            options={'db_table': 'user_account_access'},
        ),
        migrations.AddConstraint(
            model_name='useraccountaccess',
            constraint=models.UniqueConstraint(
                fields=['user', 'tenant', 'account_id'],
                name='unique_user_tenant_account',
            ),
        ),
        migrations.AddIndex(
            model_name='useraccountaccess',
            index=models.Index(fields=['user', 'tenant'], name='uaa_user_tenant_idx'),
        ),
    ]
