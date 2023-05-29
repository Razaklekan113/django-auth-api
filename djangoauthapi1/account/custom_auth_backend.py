from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class CustomAuthBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        User = get_user_model()
        # Modify the username to make it case-insensitive
        email = email.lower()
        try:
            user = User.objects.get(email__iexact=email)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            pass
        return None