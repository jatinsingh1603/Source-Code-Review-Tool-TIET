import re

EMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$")
DATE_RE = re.compile(r"(?P<year_part>\d{4})-(?P<month_part>\d{2})")
TOKEN_RE = re.compile(r"(admin|superuser)_token\d+")
