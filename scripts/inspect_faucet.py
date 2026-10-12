import urllib.request
import re

req = urllib.request.Request(
    'https://faucet.testnet.valargroup.dev/',
    headers={'User-Agent': 'Mozilla/5.0'}
)
html = urllib.request.urlopen(req).read().decode('utf-8')
print('HTML length:', len(html))

# Find form action or scripts or api calls
for line in html.split('\n'):
    if any(k in line.lower() for k in ['api', 'action', 'fetch', 'post', 'endpoint', 'script']):
        print(line[:120])
