# Placeholder — this migration was applied to the production DB
# by a prior version of the project. The file was missing from this
# repo, causing a NodeNotFoundError when building the migration graph.
# Adding it as a no-op so Django can validate the dependency chain.
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user_auth', '0001_initial'),
    ]

    operations = []
