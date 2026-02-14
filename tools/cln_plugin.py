#!/usr/bin/env python3
"""
SuperScalar CLN Plugin

Bridges Core Lightning to the SuperScalar bridge daemon via TCP.
Handles:
  - htlc_accepted hook: forwards inbound HTLCs to bridge
  - superscalar-pay RPC: sends outbound payments via bridge

Usage:
  lightningd --plugin=/path/to/cln_plugin.py \
             --superscalar-bridge-host=127.0.0.1 \
             --superscalar-bridge-port=9736
"""

import json
import socket
import sys
import threading

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 9736
bridge_sock = None
pending_htlcs = {}   # htlc_id -> onion dict for resolving
pending_pays = {}     # request_id -> continuation
lock = threading.Lock()


def log(msg):
    """Write to CLN's log via stderr."""
    sys.stderr.write(f"superscalar: {msg}\n")
    sys.stderr.flush()


def send_to_cln(response):
    """Send JSON-RPC response to CLN."""
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def send_to_bridge(msg):
    """Send newline-delimited JSON to bridge."""
    global bridge_sock
    if bridge_sock is None:
        return False
    try:
        data = json.dumps(msg) + "\n"
        bridge_sock.sendall(data.encode())
        return True
    except Exception as e:
        log(f"send_to_bridge error: {e}")
        return False


def connect_bridge():
    """Connect to the SuperScalar bridge daemon."""
    global bridge_sock
    try:
        bridge_sock = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT))
        log(f"Connected to bridge at {BRIDGE_HOST}:{BRIDGE_PORT}")
        return True
    except Exception as e:
        log(f"Failed to connect to bridge: {e}")
        return False


def bridge_reader():
    """Read responses from bridge and resolve pending HTLCs/pays."""
    global bridge_sock
    buf = b""
    while True:
        try:
            data = bridge_sock.recv(4096)
            if not data:
                log("Bridge connection closed")
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                msg = json.loads(line)
                handle_bridge_msg(msg)
        except Exception as e:
            log(f"bridge_reader error: {e}")
            break


def handle_bridge_msg(msg):
    """Handle a message from the bridge."""
    method = msg.get("method", "")

    if method == "htlc_resolve":
        htlc_id = msg.get("htlc_id")
        result = msg.get("result")
        with lock:
            rpc_id = pending_htlcs.pop(htlc_id, None)

        if rpc_id is None:
            log(f"No pending HTLC for id {htlc_id}")
            return

        if result == "fulfill":
            preimage = msg.get("preimage", "")
            send_to_cln({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "result": "resolve",
                    "payment_key": preimage
                }
            })
        else:
            reason = msg.get("reason", "unknown")
            send_to_cln({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "result": "fail",
                    "failure_message": reason
                }
            })

    elif method == "pay_request":
        bolt11 = msg.get("bolt11", "")
        request_id = msg.get("request_id", 0)
        log(f"Pay request: {bolt11[:30]}... (id={request_id})")
        # In production, call `lightning-cli pay` here
        # For now, just log it
        send_to_bridge({
            "method": "pay_result",
            "request_id": request_id,
            "success": False,
            "preimage": "00" * 32
        })


def handle_htlc_accepted(rpc_id, params):
    """Handle the htlc_accepted hook from CLN."""
    onion = params.get("onion", {})
    htlc = params.get("htlc", {})
    payment_hash = htlc.get("payment_hash", "")
    amount_msat = int(htlc.get("amount_msat", "0msat").replace("msat", ""))
    cltv_expiry = htlc.get("cltv_expiry", 0)

    # Assign local htlc_id
    with lock:
        htlc_id = len(pending_htlcs) + 1
        pending_htlcs[htlc_id] = rpc_id

    ok = send_to_bridge({
        "method": "htlc_accepted",
        "payment_hash": payment_hash,
        "amount_msat": amount_msat,
        "cltv_expiry": cltv_expiry,
        "htlc_id": htlc_id
    })

    if not ok:
        # Bridge not connected, continue normally
        send_to_cln({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"result": "continue"}
        })


def main():
    global BRIDGE_HOST, BRIDGE_PORT

    # CLN plugin initialization: read getmanifest
    for line in sys.stdin:
        request = json.loads(line)
        method = request.get("method", "")

        if method == "getmanifest":
            send_to_cln({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "dynamic": True,
                    "options": [
                        {
                            "name": "superscalar-bridge-host",
                            "type": "string",
                            "default": "127.0.0.1",
                            "description": "SuperScalar bridge host"
                        },
                        {
                            "name": "superscalar-bridge-port",
                            "type": "int",
                            "default": 9736,
                            "description": "SuperScalar bridge port"
                        }
                    ],
                    "rpcmethods": [
                        {
                            "name": "superscalar-pay",
                            "usage": "bolt11",
                            "description": "Pay via SuperScalar bridge"
                        }
                    ],
                    "hooks": [
                        {"name": "htlc_accepted"}
                    ],
                    "subscriptions": []
                }
            })

        elif method == "init":
            config = request.get("params", {}).get("options", {})
            BRIDGE_HOST = config.get("superscalar-bridge-host", BRIDGE_HOST)
            BRIDGE_PORT = int(config.get("superscalar-bridge-port", BRIDGE_PORT))

            connected = connect_bridge()
            if connected:
                t = threading.Thread(target=bridge_reader, daemon=True)
                t.start()

            send_to_cln({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {}
            })
            log(f"Plugin initialized (bridge={'connected' if connected else 'disconnected'})")

        elif method == "htlc_accepted":
            handle_htlc_accepted(request["id"], request.get("params", {}))

        elif method == "superscalar-pay":
            bolt11 = request.get("params", [""])[0] if request.get("params") else ""
            log(f"superscalar-pay: {bolt11[:30]}...")
            send_to_cln({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {"status": "not_implemented"}
            })


if __name__ == "__main__":
    main()
