# Secret connection test API

`POST /api/v1/secrets/connections/{connectionId}/test` requires a logged-in dashboard `ADMIN` and the normal CSRF header. It is synchronous and returns HTTP 200 with:

```json
{
  "connectionId": 7,
  "provider": "AWS",
  "status": "CONNECTED",
  "reasonCode": null,
  "checkedAt": "2026-10-14T01:02:03Z"
}
```

`status` is `CONNECTED`, `FAILED`, or `UNAVAILABLE`. A missing connection is 404; a paused, errored, or unsupported connection is 409; a non-admin is 403. The endpoint does not register a scan or change connection state. It returns no `auth_ref`, approved resource reference, repository name, AWS account number, credential, or provider response body.

AWS requires a valid `aws-profile:<name>` auth reference and enabled, supported scopes for exactly one account. The API uses that profile for one time-bounded STS `GetCallerIdentity` call and compares the account privately. This confirms identity, **not** IAM permission to list every service or read any particular object. It never calls Secrets Manager, SSM, S3, or IAM collection APIs.

GitHub uses the configured `SECRET_GITHUB_APP_ID`, `SECRET_GITHUB_INSTALLATION_ID`, and `SECRET_GITHUB_PRIVATE_KEY_PATH` (the same local references used by the worker). It requests a short-lived installation token limited to `contents:read` on the first enabled approved repository and checks that GitHub returned that exact repository and permission. It does not fetch repository contents or test every approved scope. When the API process lacks the local App key, the result is `UNAVAILABLE` rather than an assumed success. No provider-derived URL is followed.

Reason codes are fixed: `INVALID_APPROVED_SCOPE`, `AWS_ACCOUNT_MISMATCH`, `AWS_ACCESS_DENIED`, `AWS_RATE_LIMITED`, `AWS_UNAVAILABLE`, `GITHUB_APP_UNAVAILABLE`, `GITHUB_ACCESS_DENIED`, `GITHUB_RATE_LIMITED`, and `GITHUB_UNAVAILABLE`. Display a generic error for unknown codes. Provider exception messages and raw responses must never be logged or returned.

The existing `GET /api/v1/secrets/connections` remains the active scan picker; it does not list paused or errored connections.
