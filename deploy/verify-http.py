"""Exercise a synthetic CI API without using or printing source credentials."""
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def verify(base: str) -> None:
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def request(path, body=None):
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            token = next((c.value for c in jar if c.name == "XSRF-TOKEN"), None)
            if token:
                headers["X-XSRF-TOKEN"] = urllib.parse.unquote(token)
        req = urllib.request.Request(base + path, headers=headers,
                data=None if body is None else json.dumps(body).encode(),
                method="GET" if body is None else "POST")
        try:
            with client.open(req, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)
    for attempt in range(60):
        try:
            if request("/api/v1/auth/me")[0] == 401:
                break
        except (urllib.error.URLError, TimeoutError):
            pass
        if attempt == 59:
            raise RuntimeError("API_NOT_READY")
        time.sleep(1)
    assert request("/api/v1/secrets/summary")[0] == 401
    assert request("/api/v1/auth/login", {"loginId": "secret-ci", "password": "isolated-ci-login"})[0] == 200
    assert request("/api/v1/auth/me")[0] == 200
    status, summary = request("/api/v1/secrets/summary")
    assert status == 200
    matrix = summary["caseSummary"]["severityValidityMatrix"]
    assert matrix["status"] == "AVAILABLE" and sum(c["value"] for c in matrix["cells"]) == matrix["total"]
    status, common = request("/api/v1/overview/summary")
    assert status == 200 and common["secretIntegration"]["total"] == matrix["total"]
    print("ISOLATED_HTTP_CONTRACT_PASSED")


if __name__ == "__main__":
    if len(sys.argv) != 2 or not sys.argv[1].startswith("http://127.0.0.1:"):
        raise SystemExit("Only an isolated loopback CI endpoint is allowed")
    verify(sys.argv[1])
