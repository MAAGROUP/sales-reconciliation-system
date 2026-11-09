"""
Patch: show rejected waiter requests in the Archive page + add a status filter.
Run from the project root (where manage.py is):
    python patch_archive_views.py
A backup is saved as salesapp/views.py.bak before any change.
"""
from pathlib import Path
import shutil
import sys

path = Path('salesapp/views.py')
if not path.exists():
    sys.exit('salesapp/views.py not found. Run this from the project root.')

with open(path, 'r', encoding='utf-8', newline='') as f:
    src = f.read()

nl = '\r\n' if '\r\n' in src else '\n'

old_qs = (
    "    qs = ShiftEntry.objects.select_related('branch', 'collector')"
    ".filter(is_archived=True).exclude(request_status__in=['pending', 'rejected'])"
    ".order_by('-created_at')" + nl
)
new_qs = nl.join([
    "    qs = ShiftEntry.objects.select_related('branch', 'collector')"
    ".filter(is_archived=True).exclude(request_status='pending').order_by('-created_at')",
    "",
    "    status_filter = request.GET.get('status_filter', '').strip()",
    "    if status_filter == 'rejected':",
    "        qs = qs.filter(request_status='rejected')",
    "    elif status_filter == 'normal':",
    "        qs = qs.exclude(request_status='rejected')",
    "",
])

old_ctx = nl.join([
    "        'search_ref': search_ref,",
    "        'active_tab': 'history',",
    "",
])
new_ctx = nl.join([
    "        'search_ref': search_ref,",
    "        'status_filter': status_filter,",
    "        'active_tab': 'history',",
    "",
])

if "status_filter = request.GET.get('status_filter'" in src:
    sys.exit('Already patched. Nothing changed.')

for label, old in (('queryset line', old_qs), ('context block', old_ctx)):
    count = src.count(old)
    if count != 1:
        sys.exit(f'Could not patch safely: found the {label} {count} times (expected 1). Nothing changed.')

shutil.copyfile(path, path.with_suffix('.py.bak'))
src = src.replace(old_qs, new_qs).replace(old_ctx, new_ctx)

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(src)

print('Done. views.py patched (backup: salesapp/views.py.bak).')
