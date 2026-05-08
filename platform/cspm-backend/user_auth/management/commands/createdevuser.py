from django.core.management.base import BaseCommand
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from user_auth.models import Users


class Command(BaseCommand):
    help = 'Create a development user for testing (custom Users model)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            required=True,
            help='Email address for the user'
        )
        parser.add_argument(
            '--password',
            type=str,
            required=True,
            help='Password for the user (min 8 chars)'
        )
        parser.add_argument(
            '--first-name',
            type=str,
            default='',
            help='First name'
        )
        parser.add_argument(
            '--last-name',
            type=str,
            default='',
            help='Last name'
        )
        parser.add_argument(
            '--status',
            type=str,
            default='active',
            help='User status (default: active)'
        )

    def handle(self, *args, **options):
        email = options['email'].strip().lower()
        password = options['password']
        first_name = options['first_name']
        last_name = options['last_name']
        status = options['status']

        # Validate email
        try:
            validate_email(email)
        except ValidationError:
            self.stderr.write(
                self.style.ERROR(f'Invalid email address: {email}')
            )
            return

        # Validate password
        if len(password) < 8:
            self.stderr.write(
                self.style.ERROR('Password must be at least 8 characters long')
            )
            return

        # Check existing user
        if Users.objects.filter(email=email).exists():
            self.stdout.write(
                self.style.WARNING(f'User with email {email} already exists')
            )
            return

        # Create user
        user = Users(
            email=email,
            first_name=first_name,
            last_name=last_name,
            status=status,
            is_superuser=True,
        )
        user.set_password(password)
        user.save()

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created dev user:\n'
                f'  Email: {user.email}\n'
                f'  ID: {user.id}'
            )
        )
