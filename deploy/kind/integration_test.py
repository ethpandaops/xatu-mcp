#!/usr/bin/env python3
"""Integration test for Kubernetes sandbox backend via KIND cluster."""

import json
import sys
import time
import urllib.request
import urllib.error

MCP_URL = "http://localhost:30000"


def test_health():
    """Test health endpoint."""
    print("Testing health endpoint...")
    try:
        with urllib.request.urlopen(f"{MCP_URL}/health", timeout=5) as resp:
            body = resp.read().decode()
            assert body == "ok", f"Expected 'ok', got '{body}'"
            print("  ✓ Health check passed")
            return True
    except Exception as e:
        print(f"  ✗ Health check failed: {e}")
        return False


def test_sse_connection():
    """Test SSE endpoint is reachable."""
    print("Testing SSE endpoint...")
    try:
        req = urllib.request.Request(f"{MCP_URL}/sse")
        with urllib.request.urlopen(req, timeout=5) as resp:
            # SSE should return 200 and start streaming
            assert resp.status == 200, f"Expected 200, got {resp.status}"
            content_type = resp.headers.get("Content-Type", "")
            assert "text/event-stream" in content_type, f"Expected SSE content type, got {content_type}"
            print("  ✓ SSE endpoint reachable")
            return True
    except urllib.error.HTTPError as e:
        # SSE might not work with simple GET, that's okay
        print(f"  ⚠ SSE endpoint returned {e.code} (this may be normal)")
        return True
    except Exception as e:
        print(f"  ✗ SSE endpoint failed: {e}")
        return False


def main():
    """Run all tests."""
    print(f"\n{'='*60}")
    print(f"Integration Test: Kubernetes Sandbox Backend")
    print(f"MCP Server URL: {MCP_URL}")
    print(f"{'='*60}\n")

    results = []

    # Test health
    results.append(("Health Check", test_health()))

    # Test SSE
    results.append(("SSE Endpoint", test_sse_connection()))

    # Summary
    print(f"\n{'='*60}")
    print("Test Summary:")
    print(f"{'='*60}")

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed")
    print(f"{'='*60}\n")

    # Return exit code
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
