import sys
sys.stdout.reconfigure(encoding='utf-8')
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

options = Options()
options.add_argument('--headless')
driver = webdriver.Chrome(options=options)
try:
    driver.get('https://testnet.cipherscan.app/tx/784d8a59b56beee81de403d906d0759df5769ab3bc90bcb8975da3d8baf30208')
    time.sleep(3)
    text = driver.find_element('tag name', 'body').text
    print("=== CIPHERSCAN / ZECBLOCK PAGE CONTENT ===")
    for line in text.splitlines():
        if line.strip():
            print(line.strip())
finally:
    driver.quit()
