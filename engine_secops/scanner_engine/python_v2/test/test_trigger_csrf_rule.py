# Noncompliant example: disabling CSRF protection in Django
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def my_view(request):
    return 'Hello world'

# Compliant example: enabling CSRF protection
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def my_secure_view(request):
    return 'Hello world'
