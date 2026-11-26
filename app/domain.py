import ipaddress
import re
import json
from datetime import date, datetime


def normalize_target(kind, value):
    value = value.strip().lower()
    if kind == 'IPV4':
        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            raise ValueError('Địa chỉ IPv4 không hợp lệ.') from None
    if kind != 'DOMAIN':
        raise ValueError('Chỉ hỗ trợ IPv4 hoặc tên miền.')
    value = value.removesuffix('.')
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit() or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels):
        raise ValueError('Tên miền ASCII không hợp lệ. Không nhập URL, CIDR hoặc wildcard.')
    return value


def json_default(x):
    if isinstance(x, (date, datetime)):
        return x.isoformat()
    raise TypeError(type(x).__name__)


def dump(x):
    return None if x is None else json.dumps(x, ensure_ascii=False, default=json_default, sort_keys=True)


def snapshot(x):
    return None if x is None else json.loads(dump(x))


def parse_json(x):
    return json.loads(x) if isinstance(x, str) else x


def decision(rows):
    if any(x['list_type'] == 'BLACKLIST' for x in rows):
        return 'BLOCK', 'Khớp Blacklist; ưu tiên chặn.'
    if any(x['list_type'] == 'WHITELIST' for x in rows):
        return 'ALLOW', 'Khớp Whitelist, không khớp Blacklist.'
    return 'BLOCK', 'Không khớp Whitelist; chặn mặc định.'


def like_pattern(term, transform=None):
    """Build a safe SQL LIKE substring pattern after trimming surrounding whitespace."""
    cleaned = term.strip()
    if transform is not None:
        cleaned = transform(cleaned)
    escaped = cleaned.replace('\\', '\\\\').replace('%', r'\%').replace('_', r'\_')
    return f'%{escaped}%'
