from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_auth', '0006_invite_and_password_reset_tokens'),
    ]

    operations = [
        migrations.AddField(
            model_name='users',
            name='is_break_glass',
            field=models.BooleanField(default=False),
        ),
    ]
