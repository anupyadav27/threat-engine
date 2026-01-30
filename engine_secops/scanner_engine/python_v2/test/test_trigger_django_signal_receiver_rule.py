from django.dispatch import receiver

def my_custom_decorator(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

@my_custom_decorator
@receiver
def my_handler(sender, instance, created, **kwargs):
    pass  # Noncompliant: receiver is not the top decorator
