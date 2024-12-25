from django.http import HttpResponseBadRequest
import re

class SecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check for suspicious patterns
        if self._contains_sql_injection(request.path):
            return HttpResponseBadRequest("Invalid request")
        return self.get_response(request)

    def _contains_sql_injection(self, text):
        sql_patterns = [
            r'(\s|^)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)(\s|$)',
            r'--',
            r';',
            r'\/\*.*\*\/'
        ]
        return any(re.search(pattern, text, re.I) for pattern in sql_patterns) 