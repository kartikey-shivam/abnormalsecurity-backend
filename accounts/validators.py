from django.core.exceptions import ValidationError
import re

def validate_password_strength(password):
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain uppercase letters")
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain lowercase letters")
    if not re.search(r"[0-9]", password):
        raise ValidationError("Password must contain numbers") 