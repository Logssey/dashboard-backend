# Secret triage and response API

Detection alone does not open a case. Existing scopes start at `UNCLASSIFIED`, existing occurrences remain `UNKNOWN`, and V8 does not backfill decisions or cases. A SECURITY user explicitly classifies an approved GitHub scope, assesses a confirmed occurrence with a finding and a separate exposure reason, then opens a case.

All routes use the authenticated session. Mutations require CSRF protection. `dashboard_users.role=ADMIN` does not grant a Secret role. A current `secret_role_grants` SECURITY grant must cover the connection. In local development only, `SECRET_BOOTSTRAP_SECURITY_LOGIN_ID` may grant the configured existing account global SECURITY access; production grants need an approved provisioning process.

## Triage workflow

| Method | Path | Contract |
|---|---|---|
| GET | `/api/v1/secrets/triage-candidates?page=0&size=20` | `{items,total,page,size}`. Each item has `secretId,maskedLabel,issuer,credentialType,componentState,occurrenceCount`. Only occurrences in active approved GitHub scopes covered by the caller's SECURITY grant are counted. |
| GET | `/api/v1/secrets/triage-candidates/{secretId}` | Masked credential fields and only authorized `occurrences`. Each occurrence has `id,connectionId,scopeId,sourceObjectRef,locationKey,environment,exposureStatus,presenceStatus,assessmentVersion,scopeOrigin,scopeOriginVersion`. |
| GET | `/api/v1/secrets/scopes/{scopeId}/response-origin` | `scopeId,connectionId,scopeKey,responseOrigin,responseOriginVersion,classifiedByUserId,classifiedAt,allowedOrigins,history`. No `approved_ref` or credential value is returned. |
| PATCH | `/api/v1/secrets/scopes/{scopeId}/response-origin` | `{origin,reasonCode,expectedVersion}`. Returns the complete scope response. Only a one-time `UNCLASSIFIED` to `TEST` or `PRODUCTION` decision is supported. |
| GET | `/api/v1/secrets/occurrences/{occurrenceId}/triage` | `occurrenceId,secretId,connectionId,scopeId,componentState,exposureStatus,presenceStatus,assessmentVersion,scopeOrigin,scopeOriginVersion,openCaseId,findings,history`. Findings contain only `findingId,ruleId,detectedAt`; no detector context is returned. |
| POST | `/api/v1/secrets/occurrences/{occurrenceId}/assessments` | `{decision,reasonCode,findingId,expectedVersion}`. Returns the complete triage response. The finding must belong to that exact occurrence. |
| POST | `/api/v1/secrets/{secretId}/cases` | `{occurrenceId,reason:"ASSESSED_EXPOSURE",expectedAssessmentVersion,expectedScopeOriginVersion}`. Returns case detail with HTTP 201. |

Scope classification reason codes are `APPROVED_TEST_FIXTURE` for TEST and `APPROVED_PRODUCTION_SOURCE` for PRODUCTION. The approved `github://Logssey/test-find-key/...` fixture scope can only be classified TEST; server-side validation also prevents a PRODUCTION case on that exact repository scope. No general GitHub scope becomes PRODUCTION automatically.

Assessment decisions are `NORMAL` with `AUTHORIZED_LOCATION`, or `ABNORMAL` with `UNAPPROVED_SOURCE_LOCATION`. `SIMULATED_EXPOSURE` is an additional ABNORMAL reason allowed only in TEST scope. The `findingId` proves a detector saw the credential format at this occurrence; the reason code records the SECURITY user's independent exposure judgement. Uncertain evidence remains `UNKNOWN`. Assessment requires a CONFIRMED credential, PRESENT occurrence, active GitHub connection, enabled classified scope, current scope decision history, and the exact occurrence finding. CANDIDATE, METADATA_ONLY, missing locations, and unclassified scopes cannot be promoted through this API.

Scope decisions and occurrence assessments are append-only with actor, timestamp, previous/new state, reason, and version. A finding's identifier, rule, and scan run are snapshotted because detector retries can replace finding rows. An already opened current case blocks reassessment of its opening occurrence until disposition transitions are implemented. Mismatched expected versions return 409; classification, assessment, and case opening recheck their prerequisites under transaction locks. The current case is unique per credential and origin, keeping TEST and PRODUCTION results separate.

## Response cases and assignment

`GET /api/v1/secrets/cases?page=0&size=20&origin=PRODUCTION` returns `{items,total,page,size}` and defaults to PRODUCTION. Use `origin=TEST` explicitly for test cases. `GET /api/v1/secrets/cases/{caseId}` returns masked case detail, opening occurrence ID/reason, and assignment history. `GET /api/v1/secrets/assignees?caseId={caseId}` lists authorized REMEDIATOR users. `PATCH /api/v1/secrets/cases/{caseId}/assignment` accepts `{team,assigneeUserId,reason,expectedVersion}`; reason must be one of `INITIAL_ASSIGNMENT`, `OWNERSHIP_CHANGE`, `TEAM_TRANSFER`, `UNASSIGNED`, or `OTHER`. Team-only assignment is allowed if an eligible member belongs to that team; both null fields unassign. Assignment changes, versions, history, and case audit are written in one transaction. Stale versions return 409.

No API accepts a raw credential or free-form evidence text. The responses do not include credential values, `approved_ref`, or raw detector context. The current implementation covers manually assessed GitHub file exposure; AWS secret stores and IAM metadata remain inventory observations rather than response cases. General role provisioning and automated scope approval are outside this MVP.
