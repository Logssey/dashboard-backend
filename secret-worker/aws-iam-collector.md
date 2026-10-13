# AWS IAM metadata collector (MVP)

This opt-in worker reads only IAM access-key metadata from one explicitly approved account. An enabled `AWS` connection must use `auth_ref=aws-profile:<profile>` matching the worker's configured profile. Every enabled scope must have `content_type=IAM_ACCESS_KEY_METADATA`, `approved_ref=aws://<12-digit-account-id>/global/iam/access-keys`, and `history_limit=CURRENT_STATE_ONLY` (or no history limit). The worker calls STS `GetCallerIdentity` first and refuses to list users if the returned account differs from the approved account. IAM is global, so this scope does not iterate regions.

The adapter makes only STS `GetCallerIdentity` and IAM `GetAccountSummary`, `ListUsers`, `ListAccessKeys`, and `GetAccessKeyLastUsed` calls. It does not call `CreateAccessKey`, `GetSecretValue`, `GetParameter`, `GetObject`, or any write operation. AWS [documents that ListAccessKeys returns metadata and cannot recover a secret access key](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html). A listed ID is stored as `METADATA_ONLY` / `AWS_IAM_ACCESS_KEY`, with `UNASSESSED` severity and `UNCHECKED` validation. The latest observation's key status, creation and last-use information is available in the Secret detail API as `iamMetadata`. Status `ACTIVE` is an IAM setting, not proof that the key authenticates or grants resource access.

`ListUsers` enumerates IAM user keys, not root access keys. The collector checks [GetAccountSummary.AccountAccessKeysPresent](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html) before listing. If root keys exist, it records `AWS_ROOT_ACCESS_KEYS_PRESENT` and marks the run `PARTIAL`; it does not fetch root key values. If that summary is unavailable, it records `AWS_ROOT_KEY_COVERAGE_UNKNOWN` and also treats otherwise readable results as partial. A fully successful listing with zero keys can mark previously seen user keys missing; partial or failed listings cannot.

The IAM key ID is used in memory to ask AWS for last use, then HMACed before persistence. The DB stores the HMAC reference, a label with only the last four ID characters, and metadata observations. It stores neither the full key ID nor an IAM user name, credential material, SDK response body, or provider error text. Repeated scans deduplicate the same key in the same connection and append a new observation. The API and scheduler register only AWS connections whose enabled scopes are all supported IAM metadata scopes. Other AWS services require separate source adapters and approved scopes; this collector does not mark them scanned. A manually inserted unsupported scope ends as `SKIPPED` and makes the run partial rather than reporting zero findings.

Execution requires all of these worker-only settings, in addition to the usual DB settings:

```properties
SECRET_JOB_EXECUTOR_ENABLED=true
SECRET_AWS_COLLECTION_ENABLED=true
SECRET_AWS_PROFILE=<explicit-profile-name>
SECRET_AWS_METADATA_HMAC_KEY_BASE64=<base64-of-random-32-byte-key>
SECRET_AWS_METADATA_HMAC_KEY_VERSION=<stable-version>
```

The example placeholders are not values to commit. `SECRET_AWS_COLLECTION_ENABLED` defaults to `false`. Connection registration and migrations never start an AWS scan on their own. Keep the profile's credentials and HMAC key outside Git. Rotating the HMAC key changes identifiers and requires an explicit migration plan. The IAM metadata scope has a 1,000-user, 2,000-key, and 100-page cap; denied or incomplete reads are recorded as partial/failed coverage, not a successful zero-key scan.
