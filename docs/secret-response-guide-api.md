# Secret response guide: default guidance and optional Groq selection

Scope: GitHub and AWS credential response guidance. The guide does not execute credential rotation, change a response case, approve resolution, decide severity, or infer whether a credential is valid. All displayed text is authored on the server. The optional model can select only catalog step codes and their permitted order.

## API

Both routes use the existing authenticated session and the current case's occurrence access policy. A user who cannot read a case receives 403. An unknown case receives 404. ADMIN alone does not grant Secret access.

| Method | Route | Behavior |
|---|---|---|
| GET | `/api/v1/secrets/cases/{caseId}/guide` | Returns a useful, issuer- and stage-specific default plus readiness metadata. Never calls Groq, consumes no provider budget, and does not require CSRF. |
| POST | `/api/v1/secrets/cases/{caseId}/guide` | Existing bodyless, CSRF-protected route. Explicitly requests optional AI selection. Returns the usable default if AI is restricted, disabled, misconfigured, busy, over budget, or fails. |

The existing `version`, `source`, `title`, `steps`, and `notice` fields remain. `version` is `secret-response-guide-v2` for the issuer/stage-specific catalog and readiness contract. This is independent of severity and does not change persisted checklist `guideVersion: S2_V1`, case state, or historical/closed cases. `source` is `DEFAULT` for server defaults, and `GROQ` only after an accepted Groq selection, including a cached accepted selection. A successful HTTP response alone never means AI ran.

Additive `readiness` fields:

| Field | Meaning |
|---|---|
| `status` | `READY` for an eligible GET; `UNAVAILABLE` for an eligibility/configuration block; `GENERATED` for accepted AI selection; `FALLBACK` for a requested but unsuccessful AI selection. |
| `reasonCode` | One bounded code from the tables below. No raw provider error or configuration value is returned. |
| `aiAvailable` | Eligibility and runtime configuration allow an AI request. A temporary concurrency, rate-budget, or provider failure can still occur. |
| `aiRequested` | False for GET, true for POST. |
| `providerCalled` | This request attempted provider communication. False for GET, blocked requests, and cache hits. It does not establish that Groq processed a request. |
| `cached` | A prior selection or failure cooldown was reused without a new provider call. |

GET always returns `source: DEFAULT`, `aiRequested: false`, `providerCalled: false`, and `cached: false`. It does not replay an earlier AI result. POST may return `source: DEFAULT` with `status: FALLBACK`; consumers should retain the guide and show the reason.

## Eligibility and configuration

AI requires all of: AWS or GitHub issuer; TEST origin; a current, server-verified synthetic fixture attestation; no confirmed real credential evidence; and caller access to every case location. These checks run before every selection, including cache reuse. A repository name or a TEST label alone is insufficient. PRODUCTION cases still receive the default guide. Unsupported issuers receive generic defaults with AI unavailable.

| Reason | Meaning |
|---|---|
| `READY` | Eligible with valid local configuration; a provider call has not occurred. |
| `UNSUPPORTED_ISSUER` | AI scope covers AWS and GitHub only. |
| `TEST_ONLY` | Case origin is not TEST. |
| `SYNTHETIC_FIXTURE_REQUIRED` | The trusted fixture conditions are not satisfied. |
| `ALL_LOCATIONS_ACCESS_REQUIRED` | Caller cannot read every associated location. |
| `DISABLED` | Runtime opt-in is off. |
| `KEY_MISSING` / `KEY_INVALID` | Local API key is absent or contains an invalid header character. |
| `ENDPOINT_NOT_ALLOWED` | Endpoint or redirect policy violates the fixed destination policy. |
| `MODEL_NOT_ALLOWED` | Model is outside the explicit supported model allowlist. |
| `CONFIGURATION_INVALID` | A configured safety limit is outside its accepted range. |

Required runtime settings are `SECRET_GUIDE_GROQ_ENABLED=true` and a locally stored `GROQ_API_KEY`. The key remains server-side and must never be placed in a frontend environment, request body, screenshot, log, or committed file. Runtime defaults:

| Environment setting | Default | Accepted range/policy |
|---|---|---|
| `GROQ_API_URL` | `https://api.groq.com/openai/v1/chat/completions` | Exact HTTPS host and path, standard port, no user info, query, fragment, or redirects. Arbitrary HTTPS destinations are rejected. Loopback HTTP exists only in injected adapter tests, never runtime configuration. |
| `GROQ_MODEL` | `openai/gpt-oss-20b` | This model only. |
| `SECRET_GUIDE_GROQ_TIMEOUT_MS` | `5000` | 250–8000 milliseconds; covers response headers and complete body. |
| `SECRET_GUIDE_GROQ_CALLS_PER_MINUTE` | `6` | 1–6 calls per minute per application process. No automatic retries. |
| `SECRET_GUIDE_GROQ_CACHE_SECONDS` | `300` | 30–900 seconds for accepted selections. |

Readiness validates local settings only. It does not test provider authentication, account quota, model availability, billing tier, or network connectivity, and does not guarantee a free quota. Keep external calls opt-in; the adapter has no paid fallback.

## Provider outcomes and limits

| Reason | Meaning |
|---|---|
| `GROQ_GENERATED` | New accepted catalog-code selection. |
| `CACHE_HIT` | Accepted prior selection reused. |
| `REQUEST_IN_PROGRESS` | Another guide call is in flight in this process. No additional call was started. |
| `CALL_BUDGET_EXHAUSTED` | Process-wide minute budget is exhausted. |
| `PROVIDER_TIMEOUT` | Header/body deadline exceeded; pending request cancelled. |
| `PROVIDER_REJECTED` | Provider returned a non-rate-limit 4xx status. |
| `PROVIDER_RATE_LIMITED` | Provider returned 429. |
| `PROVIDER_UNAVAILABLE` | Network failure, redirect, unexpected status, or internal adapter failure. |
| `PROVIDER_INVALID_RESPONSE` | Malformed, refused, truncated, unknown, duplicated, or unsafe-order selection. |
| `PROVIDER_RESPONSE_TOO_LARGE` | Response exceeded 8192 bytes, including chunked bodies. |
| `PROVIDER_INTERRUPTED` | Request interrupted; pending request cancelled and thread interrupt restored. |

There is at most one provider call in flight per process. The cache holds at most 128 sanitized enum contexts. Failures have a 15-second cooldown; replay retains the original failure reason with `cached: true` and `providerCalled: false`. Process restarts clear cache and budgets; limits are not a distributed quota across replicas.

Outbound user context contains exactly five allowlisted enums: `issuer`, `credentialType`, `componentState`, `stage`, `validationStatus`. Unsupported values become `OTHER`. No key material, labels, fingerprints, case/actor IDs, repository/object paths, provider identities, evidence, or free-form text leave the application. The API requests a strict JSON schema, `reasoning_effort: low`, and at most 512 completion tokens. Accepted content is at most 2048 characters, contains only `step_codes`, includes the four required codes once, starts with `VERIFY_EXPOSURE`, ends with `REVALIDATE`, and places `EXTERNAL_ROTATION` before `RECORD_ACTION`.

## Verification

Adapter tests use a loopback mock HTTP server only. They cover exact endpoint rejection, request enum sanitization, HTTP failures, strict output/order validation, declared/chunked response bounds, stalled headers and bodies, shared concurrency, minute budget, successful cache reuse, and failure cooldown. Controller/service tests cover GET without an AI call, default provenance, precise fallback metadata, permissions, and CSRF separation. Database-backed tests verify that GET and POST leave case versions and audit history unchanged and that trusted fixture eligibility can be revoked by real-credential evidence.

No real Groq request is claimed by these tests. A live check requires the operator's local key, explicit runtime opt-in, a current approved synthetic TEST fixture, full case access, and an intentional POST. Read GET first, then inspect `source`, `providerCalled`, `reasonCode`, and `cached`; never treat a displayed default as evidence of an AI call.

Official API references checked for the request format: [Groq structured-output example](https://console.groq.com/docs/structured-outputs/scripts/step2-example.py), [chat completions](https://console.groq.com/docs/text-chat), [reasoning controls](https://console.groq.com/docs/reasoning), and [API reference](https://console.groq.com/docs/api-reference). Provider API support does not replace local validation.
