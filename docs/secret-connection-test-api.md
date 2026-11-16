# Secret connection test API

`POST /api/v1/secrets/connections/{connectionId}/test` requires a logged-in user with a live `OPERATIONS` grant for that connection and the normal CSRF header. It is synchronous and returns HTTP 200 with:

```json
{
  "connectionId": 7,
  "provider": "AWS",
  "status": "CONNECTED",
  "reasonCode": null,
  "checkedAt": "2026-10-14T01:02:03Z"
}
```

`status` is `CONNECTED`, `FAILED`, or `UNAVAILABLE`. A missing connection is 404. A paused, errored, or unsupported connection is 409. A caller without the required connection role receives 403. The endpoint does not register a scan or change connection state. It returns no `auth_ref`, approved resource reference, repository name, AWS account number, credential, or provider response body.

AWS accepts `aws-workload:default` and the existing `aws-profile:<name>` reference. Enabled, supported scopes must belong to one account. The API performs one time-bounded STS `GetCallerIdentity` call and compares the account. Collection permissions are checked when the worker executes each approved read.

GitHub uses the configured `SECRET_GITHUB_APP_ID`, `SECRET_GITHUB_INSTALLATION_ID`, and `SECRET_GITHUB_PRIVATE_KEY_PATH` (the same local references used by the worker). It requests a short-lived installation token limited to `contents:read` on the first enabled approved repository and checks that GitHub returned that exact repository and permission. It does not fetch repository contents or test every approved scope. When the API process lacks the local App key, the result is `UNAVAILABLE` rather than an assumed success. No provider-derived URL is followed.

Reason codes are fixed: `INVALID_APPROVED_SCOPE`, `AWS_ACCOUNT_MISMATCH`, `AWS_ACCESS_DENIED`, `AWS_RATE_LIMITED`, `AWS_UNAVAILABLE`, `GITHUB_APP_UNAVAILABLE`, `GITHUB_ACCESS_DENIED`, `GITHUB_RATE_LIMITED`, and `GITHUB_UNAVAILABLE`. Display a generic error for unknown codes. Provider exception messages and raw responses must never be logged or returned.

The existing `GET /api/v1/secrets/connections` remains the active scan picker; it does not list paused or errored connections.

## GitHub and AWS connection management

`logssey.secret.connections.enabled=true` enables management writes. Configure `aws-region`, `aws-account-id` and `secret-prefix` under that prefix. API and worker use their own workload roles and source credential store permissions. A global `OPERATIONS` grant permits creation. Existing connections require a live global or connection-specific `OPERATIONS` grant.

| Method and suffix under `/api/v1/secrets/connections` | Contract |
| --- | --- |
| `GET /setup-options` | Runtime capability, AWS account, regions and metadata target kinds |
| `POST /` | `provider`, `displayName`, `idempotencyKey`, optional `githubCredential` |
| `GET /{id}/settings` | Safe settings and selected targets |
| `PATCH /{id}/settings` | `expectedScopeVersion`, optional `displayName`, `status`, `githubCredential` |
| `PUT /{id}/targets` | `expectedScopeVersion`, `githubTargets`, `awsTargets` |
| `DELETE /{id}/credential?expectedScopeVersion=...` | GitHub credential deletion with seven-day recovery |
| `POST /{id}/credential/restore` | `expectedScopeVersion` restores the credential and leaves the connection paused |
| `GET /{id}/github/repositories?page=1` | Up to 100 `{fullName,defaultBranch,private}` items |
| `GET /{id}/github/branches?repository=owner/repo&page=1` | Up to 100 `{name}` items |

GitHub input contains positive integer `appId` and `installationId`, plus an RSA PKCS#1 or PKCS#8 `privateKey` PEM of at least 2048 bits and at most 32 KiB. Only Secrets Manager stores the PEM. DB rows retain the secret name and immutable remote version. A failed DB commit continues using the previous version. Request string representations and API responses exclude PEM material. Existing file-based App settings remain supported.

`githubTargets` items contain `repository`, `branch`, and `path`. An empty path selects the full repository at the current commit. Relative folders become slash-terminated prefixes. Branch slashes are URI encoded. Existing prefix references remain valid. AWS items contain `kind` and `region`. IAM key and S3 bucket metadata use `global`; Secrets Manager and Parameter metadata use the configured AWS region. Existing AWS content scopes are preserved by metadata-target edits.

Within one connection, overlapping paths in the same repository must use separate connections, including overlaps across branches. Disjoint folders remain supported. The encoded GitHub reference must fit 500 characters. Automatically generated display aliases are shortened to the existing 80-character column limit while the complete reference is retained.

Create returns HTTP 201. Settings changes return HTTP 200 with `connectionId`, `provider`, `displayName`, `status`, `scopeVersion`, `credentialConfigured`, `credentialVersion`, `githubApp`, target arrays, and credential deletion/recovery fields. New connections and changed targets or credentials are paused. Activation requires configured authentication and at least one target. Configuration changes cancel stale pending or leased jobs and retain run, finding, credential-reference and audit history.

Deleting a managed credential schedules Secrets Manager deletion with a seven-day recovery window. During that period the connection is paused and exposes `credentialDeletionPending`, `credentialRecoveryUntil`, and `canRestoreCredential`. Restore returns to a paused state. Failed DB mutations compensate the remote operation. If compensation also fails, the connection remains paused with a recovery-required audit record. Legacy shared PEM files are disconnected for that connection while the shared file remains available to other legacy connections.

After the recovery window ends, new credentials can be registered on the same connection under a fresh remote secret name. Historical version references remain immutable. Configuration changes terminate unfinished execution stages with `SOURCE_CONFIGURATION_CHANGED` and fence stale worker result writes.

## Rotated workload session files

`logssey.secret.aws.collection.credentials-file` optionally selects a read-only JSON file in `WORKLOAD` mode. API and worker can mount separate role sessions at `/run/aws/credentials.json`. The format contains `Version:1`, `AccessKeyId`, `SecretAccessKey`, `SessionToken`, and ISO-8601 `Expiration`. The provider rereads every resolution, rejects expired or incomplete files and never falls back to another identity. Publishers should replace the file atomically. No session values belong in Git, request logs or connection rows.
