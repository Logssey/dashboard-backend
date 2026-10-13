# AWS storage metadata collection (MVP)

This opt-in worker supports three additional count-only scopes alongside [IAM access-key metadata](aws-iam-collector.md):

| `content_type` | Exact `approved_ref` | AWS API |
| --- | --- | --- |
| `AWS_SECRETS_MANAGER_METADATA` | `aws://<12-digit-account>/<region>/secrets-manager/all` | Secrets Manager `ListSecrets` |
| `AWS_SSM_PARAMETER_METADATA` | `aws://<12-digit-account>/<region>/ssm/parameters` | SSM `DescribeParameters` |
| `AWS_S3_BUCKET_METADATA` | `aws://<12-digit-account>/global/s3/buckets` | S3 `ListBuckets` |

Set `history_limit=CURRENT_STATE_ONLY`. Each regional scope runs only in its approved region; the worker does not discover or iterate regions. The S3 scope lists buckets for the approved account and does not list objects. The worker checks the connection's `auth_ref=aws-profile:<profile>` against `SECRET_AWS_PROFILE`, then calls STS `GetCallerIdentity` and checks its account against each approved scope before a listing call. `SECRET_AWS_COLLECTION_ENABLED=false` (the default) leaves the collector and scheduled AWS reservations disabled. Profile credentials belong in the local AWS credential store, never in a repository.

The adapter holds provider responses in memory long enough to count entries. It discards resource names, ARNs, descriptions, tags, and continuation tokens. It never calls `GetSecretValue`, `GetParameter`, `GetParameters`, `GetObject`, `ListObjects`, or decryption APIs. A list entry only proves a resource exists; it is not a detected exposed credential. Thus these scopes do not create `secret_credential_sets` or validation attempts. IAM's separate HMAC-based key observations remain unchanged.

Each `secret_run_scopes` row stores a count, `SUCCEEDED`/`PARTIAL`/`FAILED`, and a fixed gap code. The job status API also returns `scopeResults` with content type, safe region, count, status, and gap code, but never the account ID, `approved_ref`, resource name, ARN, or provider error message. Pagination is bounded to 200 pages and 100,000 entries per scope; a denied later page records partial coverage instead of a successful zero count. The Java unit tests use injected fake SDK clients, and no test makes a live AWS call.
