# Secret assessment and AWS usage lookup

## Assessment worker

`logssey.secret.assessment.enabled` (`SECRET_ASSESSMENT_ENABLED`) defaults to `true` in the secret worker. It evaluates saved, versioned evidence only and does not enable collection, credential validation, or provider calls. Keep a secret worker process running against the same database as the API. Turning off `logssey.secret.executor.enabled` no longer stops assessment. Explicitly turn assessment off when a deployment must not process the queue.

The risk API returns `assessmentProcess` independently of the grade. `PENDING` / `RUNNING` trigger periodic UI refresh. A completed R99 result means insufficient or conflicting evidence, not a stalled worker. The UI exposes unavailable assessment workers rather than treating a queued request as successful. Metadata-only inventory is not graded as a secret exposure.

No severity rule was changed. Exposure decision, access scope, credential composition, grounded permission evidence, and asset classification determine the grade. Authentication failure does not automatically lower a previous exposure grade. Missing evidence remains unassessed.

## Enable AWS usage lookup

1. Verify the existing AWS connection and approved IAM metadata scope belong to the intended account. Select the explicit region; do not infer permission from a source credential's presence.
2. Grant the **secret worker role only** `cloudtrail:LookupEvents` in that region/account and `iam:GetUser` on that account's users, in addition to its existing IAM key inventory reads. Infrastructure `terraform/environments/logssey-dashboard/source-credentials.tf` owns these statements. No key values, CloudTrail configuration writes, or service data reads are required.
3. Run `deploy/register-usage-target.sql` with the occurrence, IAM metadata collector scope, authorized approver user and region. The script validates active connections and existing roles; it enables manual lookup, not recurring lookup. Re-register after changing approved scope revisions. Do not bypass the baseline checks.
4. Set `logssey.secret.usage.cloudtrail-enabled=true` in **both** API and worker runtime properties. Preserve backups and existing credentials/configuration. Restart those two Logssey services and wait for the API health check and a fresh `USAGE` worker heartbeat.
5. Request a bounded lookup from the key's usage history screen. Verify `COMPLETE`, exact credential binding, and persisted observations through the same authenticated API. A successful query with zero results is `NOT_OBSERVED_IN_SCOPE`, not proof the key was never used. Verify failed lookups retain a reason instead of appearing successful.

Automatic usage lookup currently supports AWS IAM access keys and identity-bound AWS key pairs. GitHub and Notion token use is not provided by CloudTrail. CloudTrail lookup covers regional management events within its retained time window; it is not a complete audit of every data access. Raw keys and raw event bodies are not returned by this API, and lookup uses the approved management identity rather than the discovered secret.

## Verification for this change

- Isolated local database: previously queued assessment jobs run with external collection disabled. Synthetic, explicitly labelled evidence fixtures cover Critical / High / Medium / Low using the real worker and policy, without changing operating service data.
- Policy integration tests verify R02–R07 results reach the risk API; missing information still produces R99. Tests also cover leases, evidence freshness, source binding and worker failure reporting.
- Production AWS activation: existing account, Tokyo region, seven IAM metadata occurrences, manual lookup only. Recorded query results distinguish events found, no events in the requested window, and access denied. No production evidence or grades are fabricated.
