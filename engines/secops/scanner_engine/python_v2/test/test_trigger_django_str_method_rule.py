from django.db import models

class MyModel(models.Model):
    pass  # Noncompliant: Missing __str__ method
