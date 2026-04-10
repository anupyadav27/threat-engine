import uuid
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_auth', '0005_rename_name_first_users_first_name_and_more'),
        ('tenant_management', '0003_alter_tenants_options_alter_tenantusers_options_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='InviteTokens',
            fields=[
                ('id', models.TextField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('token', models.TextField(unique=True)),
                ('email', models.TextField()),
                ('tenant', models.ForeignKey(
                    db_column='tenant_id',
                    on_delete=django.db.models.deletion.CASCADE,
                    to='tenant_management.tenants',
                )),
                ('role', models.ForeignKey(
                    blank=True,
                    db_column='role_id',
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to='user_auth.roles',
                )),
                ('invited_by', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='invites_sent',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('expires_at', models.DateTimeField()),
                ('used', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={'db_table': 'invite_tokens'},
        ),
        migrations.AddIndex(
            model_name='invitetokens',
            index=models.Index(fields=['token'], name='invite_token_idx'),
        ),
        migrations.AddIndex(
            model_name='invitetokens',
            index=models.Index(fields=['email'], name='invite_email_idx'),
        ),
        migrations.CreateModel(
            name='PasswordResetTokens',
            fields=[
                ('id', models.TextField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('token', models.TextField(unique=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='password_reset_tokens',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('expires_at', models.DateTimeField()),
                ('used', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={'db_table': 'password_reset_tokens'},
        ),
        migrations.AddIndex(
            model_name='passwordresettokens',
            index=models.Index(fields=['token'], name='pwd_reset_token_idx'),
        ),
    ]
