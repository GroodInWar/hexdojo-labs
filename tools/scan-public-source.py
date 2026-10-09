#!/usr/bin/env python3
"""Small release guard; complements GitHub secret scanning, never proves absence."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    'private key': rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
    'GitHub token': rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b',
    'AWS key': rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    'Stripe key': rb'\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b',
    'credential URL': rb'https?://[^\s/<>"\']+:[^\s/<>"\']+@',
}
DENIED = {'worker', 'lab-service', 'drizzle', 'db', '.openai', '.sites-runtime', '.challenge'}
failures = []
count = 0
for path in ROOT.rglob('*'):
    if any(part in {'.git', 'node_modules', '__pycache__'} for part in path.relative_to(ROOT).parts):
        continue
    if not path.is_file():
        continue
    relative = path.relative_to(ROOT)
    if set(relative.parts) & DENIED or path.name.startswith('.env') or path.suffix in {'.key', '.pem', '.pcap', '.pcapng'}:
        failures.append(f'{relative}: excluded release material')
    data = path.read_bytes()
    count += 1
    for name, pattern in PATTERNS.items():
        if re.search(pattern, data):
            failures.append(f'{relative}: {name}')
if failures:
    raise SystemExit('\n'.join(failures))
print(f'PASS release boundary and credential patterns: {count} files')
