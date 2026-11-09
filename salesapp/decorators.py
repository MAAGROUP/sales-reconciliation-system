from functools import wraps
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme

MAX_UPLOAD_BYTES = 10 * 1024 * 1024   # one limit for every file uploaded anywhere in the system


def _too_big_uploads(request):
    """Names of the uploaded files that are over the limit (empty when the request has no files)."""
    if request.method != 'POST' or not request.FILES:
        return []
    return [f.name for _, files in request.FILES.lists() for f in files if f.size > MAX_UPLOAD_BYTES]


def role_required(*allowed_roles):
    """Only allow the view if the logged-in user's profile role is in allowed_roles.
    Admin and IT (is_full_access) are always allowed, regardless of allowed_roles."""
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped(request, *args, **kwargs):
            profile = getattr(request.user, 'profile', None)
            if profile is None:
                raise PermissionDenied('Your account does not have access to this page.')
            if profile.is_full_access or profile.role in allowed_roles:
                too_big = _too_big_uploads(request)
                if too_big:
                    messages.error(request, f'Not saved: {", ".join(too_big)} is larger than 10 MB. '
                                            'Please choose a smaller file (or a lower-quality photo) and send again.')
                    back = request.META.get('HTTP_REFERER', '')
                    if not back or not url_has_allowed_host_and_scheme(back, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
                        back = '/'
                    return redirect(back)
                return view_func(request, *args, **kwargs)
            raise PermissionDenied('Your account does not have access to this page.')
        return wrapped
    return decorator
