import urllib.request
import re

req = urllib.request.Request('https://testnet.zcashexplorer.app/', headers={'User-Agent': 'Mozilla/5.0'})
html = urllib.request.urlopen(req).read().decode('utf-8')
links = re.findall(r'href=["\'](/[^"\']+)["\']', html)
print('Total links:', len(links))
for l in links[:30]:
    print('Link:', l)
