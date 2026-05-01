from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_auth', '0007_users_is_break_glass'),
    ]

    operations = [
        # Use SeparateDatabaseAndState so downstream migrations see the fields
        # but the SQL is idempotent (ADD COLUMN IF NOT EXISTS) for environments
        # where the columns already exist from manual setup.
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AddField(
                    model_name='roles',
                    name='level',
                    field=models.IntegerField(default=4),
                ),
                migrations.AddField(
                    model_name='roles',
                    name='scope_level',
                    field=models.CharField(default='tenant', max_length=50),
                ),
                migrations.AddField(
                    model_name='usersessions',
                    name='token_hint',
                    field=models.CharField(blank=True, max_length=8, null=True),
                ),
                migrations.AddField(
                    model_name='usersessions',
                    name='permissions_cache',
                    field=models.JSONField(default=list),
                ),
                migrations.AddField(
                    model_name='usersessions',
                    name='scope_cache',
                    field=models.JSONField(default=dict),
                ),
            ],
            database_operations=[
                migrations.RunSQL(
                    sql=[
                        "ALTER TABLE roles ADD COLUMN IF NOT EXISTS level integer DEFAULT 4",
                        "ALTER TABLE roles ADD COLUMN IF NOT EXISTS scope_level varchar(50) DEFAULT 'tenant'",
                        "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS token_hint varchar(8)",
                        "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS permissions_cache jsonb DEFAULT '[]'",
                        "ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS scope_cache jsonb DEFAULT '{}'",
                        "CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hint ON user_sessions(token_hint) WHERE revoked = false",
                    ],
                    reverse_sql=[
                        "DROP INDEX IF EXISTS idx_user_sessions_token_hint",
                    ],
                ),
            ],
        ),
    ]
