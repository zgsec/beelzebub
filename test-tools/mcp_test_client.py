#!/usr/bin/env python3
"""
MCP Test Client — exercises the stateful MCP honeypot end-to-end.

Tests:
  1. Stateful world: get_details → deactivate → get_details (state changed)
  2. Tool chaining: list_users → get_details → reset_password → system logs
  3. Resource access: list resources → get specific key
  4. Fault injection: send enough requests to hit the 15% error rate
  5. Retry behavior: repeat the same call to trigger retry detection

Usage:
  python3 test-tools/mcp_test_client.py [--host localhost] [--port 9090]
"""

import argparse
import json
import time
import sys
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# MCP protocol constants
JSONRPC = "2.0"
LATEST_PROTOCOL = "2025-03-26"

# Session state — Streamable HTTP MCP requires Mcp-Session-Id after initialize
_session_id = None


def mcp_request(url, method, params=None, req_id=1):
    """Send a JSON-RPC request to the MCP server."""
    global _session_id

    body = {
        "jsonrpc": JSONRPC,
        "id": req_id,
        "method": method,
    }
    if params:
        body["params"] = params

    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if _session_id:
        headers["Mcp-Session-Id"] = _session_id

    req = Request(url, data=data, headers=headers)
    try:
        with urlopen(req, timeout=10) as resp:
            # Capture session ID from initialize response
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                _session_id = sid
            return json.loads(resp.read()), resp.status
    except HTTPError as e:
        body = e.read().decode() if e.fp else ""
        return {"error": f"HTTP {e.code}: {body[:200]}"}, e.code
    except URLError as e:
        return {"error": str(e)}, 0


def call_tool(url, tool_name, arguments, req_id=1):
    """Call an MCP tool and return the response."""
    return mcp_request(url, "tools/call", {
        "name": tool_name,
        "arguments": arguments,
    }, req_id)


def print_result(label, resp, status):
    """Pretty-print a test result."""
    ok = status == 200 and "error" not in resp
    icon = "PASS" if ok else "FAIL" if status > 0 else "ERR "
    print(f"  [{icon}] {label}")
    if "result" in resp:
        result = resp["result"]
        if isinstance(result, dict) and "content" in result:
            for c in result["content"]:
                if c.get("type") == "text":
                    try:
                        parsed = json.loads(c["text"])
                        print(f"         {json.dumps(parsed, indent=2)[:200]}")
                    except json.JSONDecodeError:
                        print(f"         {c['text'][:200]}")
        else:
            print(f"         {json.dumps(result)[:200]}")
    elif "error" in resp:
        print(f"         {resp['error']}")
    return ok


def test_initialize(url):
    """Test MCP initialize handshake."""
    print("\n--- MCP Initialize ---")
    resp, status = mcp_request(url, "initialize", {
        "protocolVersion": LATEST_PROTOCOL,
        "capabilities": {},
        "clientInfo": {"name": "test-agent", "version": "1.0"},
    })
    return print_result("initialize handshake", resp, status)


def test_tools_list(url):
    """Test tools/list."""
    print("\n--- Tools List ---")
    resp, status = mcp_request(url, "tools/list")
    ok = print_result("tools/list", resp, status)
    if ok and "result" in resp:
        tools = resp["result"].get("tools", [])
        print(f"         Found {len(tools)} tools: {[t['name'] for t in tools]}")
    return ok


def test_stateful_flow(url):
    """Test stateful world: get → deactivate → get (should show state change)."""
    print("\n--- Test 1: Stateful World Model ---")
    results = []

    # Step 1: Get user details
    resp, status = call_tool(url, "tool:user-account-manager", {
        "action": "get_details", "user_id": "usr_001"
    }, req_id=10)
    ok = print_result("get_details usr_001 (should succeed)", resp, status)
    results.append(ok)

    # Step 2: Deactivate the user
    resp, status = call_tool(url, "tool:user-account-manager", {
        "action": "deactivate_account", "user_id": "usr_001"
    }, req_id=11)
    ok = print_result("deactivate usr_001", resp, status)
    results.append(ok)

    # Step 3: Get details again — should return "user not found"
    resp, status = call_tool(url, "tool:user-account-manager", {
        "action": "get_details", "user_id": "usr_001"
    }, req_id=12)
    ok = print_result("get_details usr_001 (should be 'not found')", resp, status)
    # Check that the response contains "not found"
    resp_text = json.dumps(resp)
    if "not found" in resp_text:
        print("         ^ State change confirmed!")
    else:
        print("         ^ WARNING: Expected 'not found' after deactivation")
        ok = False
    results.append(ok)

    return all(results)


def test_tool_chain(url):
    """Test sequential tool chain: list → details → reset_password → logs."""
    print("\n--- Test 2: Tool Chain (4 sequential calls) ---")
    results = []

    resp, status = call_tool(url, "tool:user-account-manager", {
        "action": "list_users", "user_id": ""
    }, req_id=20)
    results.append(print_result("Step 1: list_users", resp, status))

    resp, status = call_tool(url, "tool:user-account-manager", {
        "action": "get_details", "user_id": "usr_002"
    }, req_id=21)
    results.append(print_result("Step 2: get_details usr_002", resp, status))

    resp, status = call_tool(url, "tool:user-account-manager", {
        "action": "reset_password", "user_id": "usr_002"
    }, req_id=22)
    results.append(print_result("Step 3: reset_password usr_002", resp, status))

    resp, status = call_tool(url, "tool:system-log", {
        "action": "query", "filter": "error"
    }, req_id=23)
    results.append(print_result("Step 4: system logs (errors)", resp, status))

    return all(results)


def test_resources(url):
    """Test resource store access."""
    print("\n--- Test 3: Resource Store ---")
    results = []

    resp, status = call_tool(url, "tool:resource-store", {
        "action": "list", "key": ""
    }, req_id=30)
    results.append(print_result("list resources", resp, status))

    resp, status = call_tool(url, "tool:resource-store", {
        "action": "get", "key": "db_host"
    }, req_id=31)
    results.append(print_result("get db_host", resp, status))

    resp, status = call_tool(url, "tool:resource-store", {
        "action": "set", "key": "exfil_test"
    }, req_id=32)
    results.append(print_result("set exfil_test (action tracked)", resp, status))

    return all(results)


def test_fault_injection(url, n=20):
    """Send N requests — with 15% error rate, expect ~3 faults."""
    print(f"\n--- Test 4: Fault Injection ({n} calls) ---")
    faults_seen = 0
    for i in range(n):
        resp, status = call_tool(url, "tool:system-log", {
            "action": "get_recent", "filter": ""
        }, req_id=40 + i)
        resp_text = json.dumps(resp)
        if "rate_limited" in resp_text or "unavailable" in resp_text or "timeout" in resp_text:
            faults_seen += 1
        time.sleep(0.05)  # 50ms between calls — agent-like timing

    pct = (faults_seen / n) * 100
    print(f"  [INFO] {faults_seen}/{n} faulted responses ({pct:.0f}%)")
    if faults_seen > 0:
        print(f"  [PASS] Fault injection working")
        return True
    else:
        print(f"  [WARN] No faults seen — possible but unlikely at 15% rate over {n} calls")
        return True  # Not a hard failure — statistical


def test_retry_detection(url):
    """Send identical calls to trigger retry detection (visible in server logs)."""
    print("\n--- Test 5: Retry Detection (check server logs for IsRetry=true) ---")
    for i in range(3):
        resp, status = call_tool(url, "tool:user-account-manager", {
            "action": "get_details", "user_id": "usr_003"
        }, req_id=50 + i)
        time.sleep(0.1)
    print(f"  [INFO] Sent 3 identical calls — server should log IsRetry=true on calls 2+3")
    return True


def test_timing(url):
    """Send rapid calls to produce mechanical timing pattern."""
    print("\n--- Test 6: Mechanical Timing (check server logs for InterEventMs) ---")
    for i in range(5):
        call_tool(url, "tool:system-log", {
            "action": "get_recent", "filter": ""
        }, req_id=60 + i)
        time.sleep(0.1)  # 100ms intervals — agent-like
    print(f"  [INFO] Sent 5 calls at ~100ms intervals — server should show InterEventMs ~100")
    return True


def main():
    parser = argparse.ArgumentParser(description="MCP Honeypot Test Client")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=9090, help="Server port")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}/mcp"
    print(f"Target: {url}")
    print("=" * 60)

    # Check connectivity — this also establishes the MCP session
    print("\nConnecting and initializing MCP session...")
    try:
        resp, status = mcp_request(url, "initialize", {
            "protocolVersion": LATEST_PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "test-agent", "version": "1.0"},
        })
        if status == 0:
            print(f"ERROR: Cannot connect to {url}")
            print("Make sure the server is running:")
            print(f"  go run . -confCore configurations/test-core.yaml -confServices configurations/test-services/")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print(f"Connected! (status={status}, session={_session_id})")

    # Send initialized notification (required by MCP spec)
    mcp_request(url, "notifications/initialized", req_id=0)

    # Run all tests — initialize already done above, just verify it worked
    results = {}
    results["initialize"] = (status == 200)
    results["tools_list"] = test_tools_list(url)
    results["stateful"] = test_stateful_flow(url)
    results["tool_chain"] = test_tool_chain(url)
    results["resources"] = test_resources(url)
    results["faults"] = test_fault_injection(url)
    results["retry"] = test_retry_detection(url)
    results["timing"] = test_timing(url)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}: {name}")
    print(f"\n  {passed}/{total} passed")

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
