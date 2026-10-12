import urllib.request
import re
import json

url = 'https://testnet.cipherscan.app/tx/784d8a59b56beee81de403d906d0759df5769ab3bc90bcb8975da3d8baf30208'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
html = urllib.request.urlopen(req).read().decode('utf-8')

m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html)
if m:
    data = json.loads(m.group(1))
    props = data.get('props', {}).get('pageProps', {})
    print("Page props keys:", list(props.keys()))
    print("Data summary:")
    print(json.dumps(props, indent=2)[:2000])
else:
    print("No __NEXT_DATA__ found")
