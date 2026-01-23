#!/usr/bin/env python3
"""
Create first user in Django database
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cspm.settings')
django.setup()

from user_auth.models import Users

# Create user
email = 'ayushajha11@gmail.com'
password = 'Ayush@6112'

try:
    # Check if user exists
    if Users.objects.filter(email=email).exists():
        user = Users.objects.get(email=email)
        print(f'User {email} already exists')
    else:
        user = Users(email=email, name_first='Ayush', name_last='Jha', status='active')
        user.set_password(password)
        user.save()
        print(f'✅ User created: {email}')
    
    # Verify
    print(f'\nUser details:')
    print(f'  ID: {user.id}')
    print(f'  Email: {user.email}')
    print(f'  Name: {user.name_first} {user.name_last}')
    print(f'  Status: {user.status}')
    print(f'  Has password: {bool(user.password)}')
    
    print(f'\nTotal users in database: {Users.objects.count()}')
    
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

