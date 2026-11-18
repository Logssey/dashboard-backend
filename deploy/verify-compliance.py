"""Synthetic compliance E2E: request -> Worker -> OCSF import -> three frameworks -> report."""
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

    def request(path: str, body=None, expect_json=True, method=None):
        headers = {"Accept": "application/json" if expect_json else "text/html"}
        data = None
        request_method = method or "GET"
        if body is not None:
            request_method = method or "POST"
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            token = next((cookie.value for cookie in jar if cookie.name == "XSRF-TOKEN"), None)
            if token:
                headers["X-XSRF-TOKEN"] = urllib.parse.unquote(token)
        req = urllib.request.Request(base + path, data=data, headers=headers, method=request_method)
        try:
            with client.open(req, timeout=10) as response:
                payload = response.read()
                return response.status, json.loads(payload) if expect_json else payload.decode()
        except urllib.error.HTTPError as error:
            payload = error.read()
            try:
                parsed = json.loads(payload)
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = {"message": "non-json error"}
            return error.code, parsed

    for attempt in range(60):
        try:
            if request("/api/v1/auth/me")[0] == 401:
                break
        except (urllib.error.URLError, TimeoutError):
            pass
        if attempt == 59:
            raise RuntimeError("COMPLIANCE_API_NOT_READY")
        time.sleep(1)

    for attempt in range(30):
        status, _ = request("/api/v1/auth/login", {"loginId": "compliance-ci", "password": "isolated-ci-login"})
        if status == 200:
            break
        if attempt == 29:
            raise RuntimeError("COMPLIANCE_LOGIN_NOT_READY")
        request("/api/v1/auth/me")
        time.sleep(1)

    status, target = request("/api/v1/compliance/targets", {
        "targetKey": "synthetic-service",
        "displayName": "Synthetic Service",
        "awsAccountId": "000000000000",
        "roleArn": "arn:aws:iam::000000000000:role/LogsseyProwlerScan",
        "defaultRegions": ["ap-northeast-2"],
        "assessmentProfile": {
            "schemaVersion": 1,
            "serviceUsage": {"securityhub": "USED"},
            "requirements": {"MULTI_REGION": "NOT_REQUIRED"},
        },
    })
    assert status == 200 and target["connectionStatus"] == "NOT_TESTED"
    assert target["externalId"].startswith("logssey-")
    assert target["assessmentProfile"]["serviceUsage"] == {"securityhub": "USED"}

    status, connection = request("/api/v1/compliance/targets/synthetic-service/connection-tests", {})
    assert status == 200 and connection["status"] == "QUEUED"
    connection_job = connection["jobId"]
    for _ in range(45):
        status, job = request(f"/api/v1/compliance/jobs/{connection_job}?targetKey=synthetic-service")
        assert status == 200
        if job["status"] == "SUCCEEDED":
            break
        if job["status"] in ("FAILED", "CANCELLED"):
            raise RuntimeError(f"COMPLIANCE_CONNECTION_{job['status']}_{job.get('errorCode')}")
        time.sleep(1)
    else:
        raise RuntimeError("COMPLIANCE_CONNECTION_TIMEOUT")

    status, target = request("/api/v1/compliance/targets/synthetic-service")
    assert status == 200 and target["connectionStatus"] == "VERIFIED"
    status, target = request("/api/v1/compliance/targets/synthetic-service", {
        "expectedVersion": target["version"],
        "displayName": target["displayName"],
        "awsAccountId": target["awsAccountId"],
        "roleArn": target["roleArn"],
        "defaultRegions": target["defaultRegions"],
        "enabled": True,
    }, method="PATCH")
    assert status == 200 and target["enabled"] is True
    assert target["assessmentProfile"]["requirements"] == {"MULTI_REGION": "NOT_REQUIRED"}

    status, created = request("/api/v1/compliance/jobs", {
        "targetKey": "synthetic-service",
        "environment": "prod",
        "scope": {"regions": ["ap-northeast-2"], "services": ["securityhub"], "checks": []},
    })
    assert status == 200 and created["status"] == "QUEUED"
    job_id = created["jobId"]

    for _ in range(90):
        status, job = request(f"/api/v1/compliance/jobs/{job_id}?targetKey=synthetic-service")
        assert status == 200
        if job["status"] == "SUCCEEDED":
            break
        if job["status"] in ("FAILED", "CANCELLED"):
            raise RuntimeError(f"COMPLIANCE_JOB_{job['status']}")
        time.sleep(1)
    else:
        raise RuntimeError("COMPLIANCE_JOB_TIMEOUT")

    run_id = job["runId"]
    assert isinstance(run_id, int) and run_id > 0
    status, overview = request("/api/v1/compliance/overview?targetKey=synthetic-service&environment=PROD")
    assert status == 200 and overview["latestRun"]["runId"] == run_id
    assert {item["id"] for item in overview["frameworks"]} == {"isms", "iso", "csap"}
    assert overview["latestRun"]["counts"]["fail"] == 1

    status, detail = request(f"/api/v1/compliance/runs/{run_id}?targetKey=synthetic-service")
    assert status == 200
    context = detail["assessmentContext"]
    assert context["policyVersion"] == "2026-11-18.2"
    assert context["profile"]["serviceUsage"] == {"securityhub": "USED"}
    assert context["profile"]["requirements"] == {"MULTI_REGION": "NOT_REQUIRED"}
    assert context["inferredServices"] == []

    status, report = request(
        f"/api/v1/compliance/runs/{run_id}/report?targetKey=synthetic-service&framework=all",
        expect_json=False,
    )
    assert status == 200
    assert "ISMS-P" in report and "ISO/IEC 27001" in report and "CSAP" in report
    assert "인증 적합 판정이 아닙니다" in report
    assert "판정 정책" in report and "정책 2026-11-18.2" in report
    assert "적용성 프로필" in report and "서비스 사용 1" in report and "비요구 1" in report
    print("SYNTHETIC_COMPLIANCE_E2E_PASSED")


if __name__ == "__main__":
    if len(sys.argv) != 2 or not sys.argv[1].startswith("http://127.0.0.1:"):
        raise SystemExit("Only an isolated loopback CI endpoint is allowed")
    verify(sys.argv[1])
