#!/usr/bin/env python3
"""
DarkBatch Local EVM JSON-RPC Test Server
Provides a standalone HTTP JSON-RPC 2.0 server backed by EthereumTesterProvider (py-evm).
Serves as an automatic zero-dependency local EVM test node when Anvil or Hardhat is not running.
"""

import sys
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from web3 import Web3, EthereumTesterProvider
from eth_account import Account

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("darkbatch.evm_node")

w3_node = Web3(EthereumTesterProvider())

# Fund standard test accounts if needed
KNOWN_TEST_ACCOUNTS = [
    # Anvil/Hardhat #0
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    # Anvil/Hardhat #1
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
]

class JSONRPCHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress routine access logs for clean console
        pass

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len)

        try:
            req = json.loads(post_body.decode("utf-8"))
        except Exception as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"Invalid JSON: {e}"}).encode())
            return

        if isinstance(req, list):
            # Batch request
            responses = []
            for sub_req in req:
                responses.append(self.handle_single_request(sub_req))
            resp_bytes = json.dumps(responses).encode("utf-8")
        else:
            resp = self.handle_single_request(req)
            resp_bytes = json.dumps(resp).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

    def handle_single_request(self, req: dict) -> dict:
        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params", [])

        # Special cases or custom handlers
        if method == "eth_chainId":
            # Chain ID 31337 or eth-tester default (1337)
            return {"jsonrpc": "2.0", "id": req_id, "result": hex(1337)}
        elif method == "net_version":
            return {"jsonrpc": "2.0", "id": req_id, "result": "1337"}

        try:
            res = w3_node.provider.make_request(method, params)
            if "id" in res:
                res["id"] = req_id
            return res
        except Exception as e:
            logger.debug(f"RPC method {method} failed: {e}")
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": str(e)}
            }

def run_server(port: int = 8545, host: str = "127.0.0.1"):
    server_address = (host, port)
    httpd = HTTPServer(server_address, JSONRPCHandler)
    logger.info(f"DarkBatch Local EVM Node running on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping local EVM server.")
        httpd.server_close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DarkBatch Local EVM JSON-RPC Server")
    parser.add_argument("--port", type=int, default=8545, help="Listening port")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Listening host")
    args = parser.parse_args()
    run_server(port=args.port, host=args.host)
