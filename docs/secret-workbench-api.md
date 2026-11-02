# Secret case distributions

`GET /api/v1/secrets/summary` keeps work cards in their existing units. Its
`caseSummary` counts only the caller's visible current ResponseCases in the selected
origin. Inventory, unclassified scopes, locations awaiting a decision, TEST cases in
a PRODUCTION query, and hidden locations do not inflate this denominator.

`caseSummary.severityValidityMatrix` contains `scope=currentCases`,
`unit=ResponseCase`, `status`, `reasonCode`, `total`, `rows`, `columns`, `cells`, and
`staleValidationCaseCount`. Rows are CRITICAL, HIGH, MEDIUM, LOW, UNASSESSED, and
NOT_APPLICABLE; columns are VALID, INVALID, UNKNOWN, and UNCHECKED. Every available
case appears in exactly one cell. `severityCounts` retains its five original keys;
`notApplicableCaseCount` explains the separate excluded assessment category. A held
effective grade remains visible alongside its unassessed/held location counts.
Aggregation does not change severity-v2 rules or write assessment records.

Each cell returns `{severity,validity,value,queueFilter}`. Follow the filter to
`GET /api/v1/secrets/review-queue?bucket=CURRENT_CASES` or
`GET /api/v1/secrets/cases?scope=currentCases`, keeping the workbench filters and
`snapshotId`, and applying `severity` and `validity`. These two dimensions filter the
frozen set after snapshot validation; they do not produce a different snapshot.
They default to ALL, and non-case queues reject selected cell filters. The standalone
`GET /api/v1/secrets/matrix` endpoint accepts the summary filters and snapshot ID and
returns the same matrix plus its read metadata.

Case projections add `validationStatus`, `validationFreshness`,
`lastValidationStatus`, `validationCheckedAt`, `validationDueAt`, and
`validationReasonCode`. The latest visible attempt wins, including an unsuccessful
attempt. A material action still awaiting verification at an unresolved visible
location yields UNCHECKED; another location's prior success cannot bypass it. A
conclusive observation older than the existing six-hour verification window is
UNKNOWN in the current matrix, with STALE and its original result/time retained.
A snapshot containing a currently conclusive observation expires at that deadline
if earlier than its normal expiry. This prevents an old snapshot from presenting
expired authentication evidence as current. INVALID remains authentication rejection,
not proof of provider revocation or safe removal.

Counts use live ACL before grouping and the same persisted workbench snapshot for
summary, matrix, and destination list. A restricted caller gets visible-scope counts.
An OPERATIONS-only caller receives NOT_AUTHORIZED, null totals, and no matrix cells,
not a false zero. Existing authorization-revision, invalidation, and snapshot-expiry
checks still apply. No new schema migration is required.
Snapshots created before matrix facts existed return LEGACY_UNAVAILABLE with
LEGACY_SNAPSHOT_FACTS and null matrix totals. Refresh the summary without a snapshot
ID; missing historic projections are never shown as zero observations.
