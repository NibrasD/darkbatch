import sys
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

addr = "utest1twszdewhj55y0xj09dkqdz7wrselvx45n22eyj0gzvlx9lss6hkrftz9sjv8st7pt4s6l0nrlxupuwx22m53alc9gxy9ex9xfugu56hs"

options = Options()
options.add_argument("--headless")
driver = webdriver.Chrome(options=options)

try:
    print(f"Connecting to Valar Testnet Faucet for address: {addr[:25]}...")
    driver.get("https://faucet.testnet.valargroup.dev/")
    time.sleep(3)

    inputs = driver.find_elements("tag name", "input")
    if not inputs:
        print("No input found!")
        sys.exit(1)

    inputs[0].clear()
    inputs[0].send_keys(addr)
    time.sleep(1)

    buttons = driver.find_elements("tag name", "button")
    req_btn = None
    for b in buttons:
        if "Request" in b.text:
            req_btn = b
            break

    if not req_btn:
        print("Request button not found!")
        sys.exit(1)

    print(f"Found button: '{req_btn.text}'. Clicking...")
    req_btn.click()

    for i in range(20):
        time.sleep(1)
        text = driver.find_element("tag name", "body").text
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        matching = [l for l in lines if any(k in l.lower() for k in ["sent", "tx", "txid", "success", "error", "rate", "payout", "queued", "broadcast"])]
        if matching:
            print(f"Result (t={i}s):", matching)
            # check if txid or success found
            for m in matching:
                if len(m) == 64 and all(c in "0123456789abcdefABCDEF" for c in m):
                    print(">>> REAL ON-CHAIN TXID FOUND:", m)
            if any("sent" in m.lower() or "success" in m.lower() or "tx" in m.lower() for m in matching):
                time.sleep(2)
                print("Final status lines:", lines[-10:])
                break

finally:
    driver.quit()
