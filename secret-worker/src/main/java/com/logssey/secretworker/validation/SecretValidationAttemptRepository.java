package com.logssey.secretworker.validation;

import com.logssey.secretworker.*;
import com.logssey.secretworker.detection.SecretFindingNormalizer;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Durable reservations and budgets. Provider calls never run while holding a database transaction.
 */
@Repository
public class SecretValidationAttemptRepository {
    public static final String PROFILE = "credential-validation-v1";
    private final JdbcTemplate jdbc;
    private final SecretJobExecutionService jobs;

    public SecretValidationAttemptRepository(JdbcTemplate jdbc, SecretJobExecutionService jobs) {
        this.jdbc = jdbc;
        this.jobs = jobs;
    }

    public JdbcTemplate jdbcTemplate() {
        return jdbc;
    }

    public AwsValidationResult validateAws(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            AwsKeyMaterial material,
            boolean fixture,
            AwsValidationService validator) {
        return validateAws(job, credential, material, fixture, validator, null);
    }

    public AwsValidationResult validateAws(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            AwsKeyMaterial material,
            boolean fixture,
            AwsValidationService validator,
            Long sourceRunScopeId) {
        return validateAws(
                job, credential, material, fixture, validator, sourceRunScopeId, null, null);
    }

    public AwsValidationResult validateAws(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            AwsKeyMaterial material,
            boolean fixture,
            AwsValidationService validator,
            Long sourceRunScopeId,
            String sourceRef,
            String sourceVersion) {
        var result =
                validate(
                        job,
                        credential,
                        AwsValidationResult.METHOD,
                        AwsValidationResult.VERSION,
                        "AWS_STS",
                        fixture,
                        validator.enabled(),
                        () -> {
                            var aws = validator.validate(material);
                            return new CredentialValidationResult(
                                    aws.status().name(),
                                    aws.reason().name(),
                                    aws.checkedAt(),
                                    null,
                                    null,aws.identity());
                        },
                        sourceRunScopeId,
                        sourceRef,
                        sourceVersion);
        AwsValidationResult.Reason reason;
        try {
            reason = AwsValidationResult.Reason.valueOf(result.reasonCode());
        } catch (IllegalArgumentException unsupported) {
            reason = AwsValidationResult.Reason.CLIENT_FAILURE;
        }
        return new AwsValidationResult(
                AwsValidationResult.Status.valueOf(result.result()),
                reason,
                Instant.now(),
                result.providerCheckedAt(),
                AwsValidationResult.METHOD,
                AwsValidationResult.VERSION,result.identity());
    }

    public CredentialValidationResult validateGitHub(
            ClaimedSecretJob job,
            SecretFindingNormalizer.GitHubCandidate candidate,
            GitHubPatValidator validator,
            Long sourceRunScopeId,
            String sourceRef,
            String sourceVersion) {
        return validate(
                job,
                candidate.credential(),
                GitHubPatValidator.METHOD,
                GitHubPatValidator.VERSION,
                "GITHUB_USER",
                false,
                validator.enabled(),
                () -> validator.validate(candidate.token()),
                sourceRunScopeId,
                sourceRef,
                sourceVersion);
    }

    public CredentialValidationResult validateNotion(
            ClaimedSecretJob job,
            SecretFindingNormalizer.NotionCandidate candidate,
            NotionTokenValidator validator,
            Long sourceRunScopeId,
            String sourceRef,
            String sourceVersion) {
        return validate(job, candidate.credential(), NotionTokenValidator.METHOD,
                NotionTokenValidator.VERSION, "NOTION_SELF", false, validator.enabled(),
                () -> validator.validate(candidate.token()), sourceRunScopeId, sourceRef, sourceVersion);
    }

    public CredentialValidationResult validate(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            String validator,
            String version,
            String endpoint,
            boolean fixture,
            boolean enabled,
            Supplier<CredentialValidationResult> call) {
        return validate(
                job, credential, validator, version, endpoint, fixture, enabled, call, null);
    }

    public CredentialValidationResult validate(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            String validator,
            String version,
            String endpoint,
            boolean fixture,
            boolean enabled,
            Supplier<CredentialValidationResult> call,
            Long sourceRunScopeId) {
        return validate(
                job,
                credential,
                validator,
                version,
                endpoint,
                fixture,
                enabled,
                call,
                sourceRunScopeId,
                null,
                null);
    }

    public CredentialValidationResult validate(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            String validator,
            String version,
            String endpoint,
            boolean fixture,
            boolean enabled,
            Supplier<CredentialValidationResult> call,
            Long sourceRunScopeId,
            String sourceRef,
            String sourceVersion) {
        if (!registered(credential, validator, version, endpoint))
            return recordUnsupported(job, credential, sourceRunScopeId);
        return safely(
                () -> {
                    var c = findContext(job, credential, sourceRunScopeId, sourceRef);
                    if (c != null
                            && sourceRef != null
                            && !Objects.equals(sourceRef, c.get("source_object_ref")))
                        return CredentialValidationResult.unchecked("CREDENTIAL_MISMATCH");
                    if (c == null)
                        return CredentialValidationResult.unchecked("CREDENTIAL_MISMATCH");
                    String reason = preflight(c, fixture, enabled);
                    if (reason != null) {
                        var result = CredentialValidationResult.unchecked(reason);
                        recordBlocked(job, c, validator, version, endpoint, result);
                        return result;
                    }
                    var reservation = reserve(job, c, validator, version, endpoint);
                    if (reservation.reused() != null) return reservation.reused();
                    if (reservation.id() == 0)
                        return CredentialValidationResult.unchecked("RATE_BUDGET_EXHAUSTED");
                    if (sourceRef != null)
                        captureSource(job, reservation, sourceRef, sourceVersion);
                    boolean ready = false, sentBoundaryRecorded = false;
                    for (int refresh = 0; refresh < 3; refresh++) {
                        var permit = sendPermit(job, reservation);
                        if (permit.blocked() != null) {
                            var stopped =
                                    sentBoundaryRecorded
                                                    && "UNCHECKED".equals(permit.blocked().result())
                                            ? new CredentialValidationResult(
                                                    "UNKNOWN",
                                                    permit.blocked().reasonCode(),
                                                    null,
                                                    null,
                                                    permit.blocked().nextDueAt())
                                            : permit.blocked();
                            complete(job, reservation, stopped);
                            return stopped;
                        }
                        sentBoundaryRecorded = true;
                        if (System.nanoTime() - permit.issuedAtNanos()
                                <= Duration.ofSeconds(1).toNanos()) {
                            ready = true;
                            break;
                        }
                    }
                    if (!ready) {
                        var expired = CredentialValidationResult.unknown("CLIENT_FAILURE");
                        complete(job, reservation, expired);
                        return expired;
                    }
                    CredentialValidationResult result;
                    try {
                        result = Objects.requireNonNull(call.get());
                    } catch (RuntimeException ignored) {
                        result = CredentialValidationResult.unknown("CLIENT_FAILURE");
                    }
                    // SENT records the durable handoff boundary. A late client-side refusal is not
                    // a no-send proof.
                    if ("UNCHECKED".equals(result.result()))
                        result = CredentialValidationResult.unknown("CLIENT_FAILURE");
                    if (result.retryable() && result.nextDueAt() == null)
                        result =
                                new CredentialValidationResult(
                                        result.result(),
                                        result.reasonCode(),
                                        result.providerCheckedAt(),
                                        result.httpStatus(),
                                        Instant.now()
                                                .plusSeconds(
                                                        Math.min(
                                                                        900,
                                                                        30L
                                                                                << Math.min(
                                                                                        job
                                                                                                        .attemptNo()
                                                                                                - 1,
                                                                                        4))
                                                                + Math.floorMod(
                                                                        reservation
                                                                                .token()
                                                                                .hashCode(),
                                                                        10)));
                    complete(job, reservation, result);
                    return result;
                });
    }

    private static boolean registered(
            SecretFindingNormalizer.Credential credential,
            String validator,
            String version,
            String endpoint) {
        if (credential == null || !"1".equals(version)) return false;
        return ("AWS".equals(credential.issuer())
                        && Set.of("AWS_ACCESS_KEY_PAIR", "AWS_TEMPORARY_CREDENTIALS")
                                .contains(credential.credentialType())
                        && AwsValidationResult.METHOD.equals(validator)
                        && "AWS_STS".equals(endpoint))
                || ("GITHUB".equals(credential.issuer())
                        && Set.of("GITHUB_CLASSIC_PAT", "GITHUB_FINE_GRAINED_PAT")
                                .contains(credential.credentialType())
                        && GitHubPatValidator.METHOD.equals(validator)
                        && "GITHUB_USER".equals(endpoint))
                || ("NOTION".equals(credential.issuer())
                        && "NOTION_CONNECTION_TOKEN".equals(credential.credentialType())
                        && NotionTokenValidator.METHOD.equals(validator)
                        && "NOTION_SELF".equals(endpoint));
    }

    public CredentialValidationResult recordUnsupported(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            Long sourceRunScopeId) {
        return safely(
                () -> {
                    var c = findContext(job, credential, sourceRunScopeId);
                    var result =
                            CredentialValidationResult.unchecked(
                                    c != null && Boolean.TRUE.equals(c.get("synthetic_fixture"))
                                            ? "SYNTHETIC_FIXTURE"
                                            : c != null
                                                            && Boolean.TRUE.equals(
                                                                    c.get("source_guard_blocked"))
                                                    ? "SOURCE_GUARD_BLOCKED"
                                                    : "UNSUPPORTED_TYPE");
                    if (c != null)
                        recordBlocked(job, c, "UNREGISTERED", "registry-v1", "NONE", result);
                    return result;
                });
    }

    /** Legacy safe-result entrypoint. New callers reserve before provider execution. */
    @Deprecated
    public boolean recordIfLeased(
            long jobId,
            String token,
            long runId,
            SecretFindingNormalizer.Credential credential,
            AwsValidationResult result) {
        if (credential == null
                || result == null
                || !"AWS".equals(credential.issuer())
                || !AwsValidationResult.METHOD.equals(result.method())
                || !AwsValidationResult.VERSION.equals(result.version()))
            throw new IllegalArgumentException("INVALID_VALIDATION_RESULT");
        var job =
                new ClaimedSecretJob(
                        jobId, runId, 0, 1, token, OffsetDateTime.now().plusSeconds(1));
        var c = findContext(job, credential);
        if (c == null) throw new IllegalArgumentException("VALIDATION_IDENTITY_NOT_FOUND");
        if (!"CONFIRMED".equals(credential.componentState())
                && result.status() != AwsValidationResult.Status.UNCHECKED)
            throw new IllegalArgumentException("INVALID_VALIDATION_RESULT");
        return jobs.persistIfLeased(
                jobId,
                token,
                () ->
                        jdbc.update(
                                """
INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,
 requested_at,completed_at,provider_checked_at,result,reason_code,evidence_version,current_eligible,ineligible_reason_code)
VALUES(?,?,?,?,?,'AWS_STS',?,?,?,?,?,0,false,'LEGACY_UNAVAILABLE')
""",
                                num(c, "credential_set_id"),
                                runId,
                                jobId,
                                result.method(),
                                result.version(),
                                utc(result.evaluatedAt()),
                                utc(
                                        result.checkedAt() == null
                                                ? result.evaluatedAt()
                                                : result.checkedAt()),
                                utc(result.checkedAt()),
                                result.status().name(),
                                result.reason().name()));
    }

    public Map<String, Object> manualTarget(ClaimedSecretJob job) {
        return jdbc
                .queryForList(
                        """
SELECT v.*,o.source_object_ref,o.location_key,k.fingerprint,k.candidate_locator,j.expected_context->>'contextVersion' AS expected_context_version,
 s.approved_ref,s.history_limit,s.content_type FROM secret_jobs j JOIN secret_validation_context v ON v.occurrence_id=j.target_occurrence_id AND v.connection_id=j.connection_id
 JOIN secret_occurrences o USING(occurrence_id) JOIN secret_credential_sets k ON k.credential_set_id=v.credential_set_id
 JOIN secret_connection_scopes s ON s.scope_id=v.scope_id WHERE j.job_id=? AND j.purpose='CREDENTIAL_VALIDITY'
""",
                        job.jobId())
                .stream()
                .findFirst()
                .orElse(null);
    }

    public boolean isManual(ClaimedSecretJob job) {
        return Boolean.TRUE.equals(
                jdbc.queryForObject(
                        "SELECT purpose='CREDENTIAL_VALIDITY' FROM secret_jobs WHERE job_id=?",
                        Boolean.class,
                        job.jobId()));
    }

    public boolean hasRetryable(ClaimedSecretJob job) {
        return Boolean.TRUE.equals(
                jdbc.queryForObject(
                        "SELECT EXISTS(SELECT 1 FROM secret_validation_attempts WHERE run_id=? AND"
                            + " attempt_no=? AND attempt_state='COMPLETED' AND reason_code"
                            + " IN('RATE_LIMITED','PROVIDER_UNAVAILABLE','CLIENT_FAILURE','RATE_BUDGET_EXHAUSTED'))",
                        Boolean.class,
                        job.runId(),
                        job.attemptNo()));
    }

    public CredentialRevalidationProcessor processor(
            com.logssey.secretworker.detection.SecretFindingNormalizer normalizer,
            com.logssey.secretworker.detector.SecretContentDetector detector,
            AwsValidationService aws) {
        return new CredentialRevalidationProcessor(jdbc, normalizer, detector, this, aws);
    }

    public void recordSourceFailure(ClaimedSecretJob job, String reason) {
        finishManualPreparation(job, CredentialValidationResult.unknown(reason));
    }

    public boolean matchesTarget(
            Map<String, Object> target, SecretFindingNormalizer.Credential credential) {
        return Objects.equals(target.get("issuer"), credential.issuer())
                && Objects.equals(target.get("credential_type"), credential.credentialType())
                && Objects.equals(
                        target.get("fingerprint_key_version"), credential.fingerprintKeyVersion())
                && "CONFIRMED".equals(credential.componentState())
                && MessageDigest.isEqual(
                        (byte[]) target.get("fingerprint"), credential.fingerprint());
    }

    public boolean targetCurrent(Map<String, Object> target) {
        return target != null
                && Objects.equals(
                        target.get("context_version"), target.get("expected_context_version"));
    }

    public String manualBlockReason(
            ClaimedSecretJob job, Map<String, Object> target, boolean enabled) {
        return !requesterAllowed(job) ? "NOT_AUTHORIZED" : preflight(target, false, enabled);
    }

    public void recordManualBlocked(ClaimedSecretJob job, String reason) {
        finishManualPreparation(job, CredentialValidationResult.unchecked(reason));
    }

    public CredentialValidationResult prepareManual(
            ClaimedSecretJob job, Map<String, Object> target) {
        var r = reserve(job, target, method(target), "1", endpoint(target));
        // A retry may reuse an observation only after the source has been fetched and HMAC-matched
        // again.
        return r.reused() != null
                ? Set.of("VALID", "INVALID").contains(r.reused().result()) ? null : r.reused()
                : r.id() == 0
                        ? CredentialValidationResult.unchecked("RATE_BUDGET_EXHAUSTED")
                        : null;
    }

    private void finishManualPreparation(ClaimedSecretJob job, CredentialValidationResult result) {
        var c = manualTarget(job);
        if (c == null) return;
        var rows =
                jdbc.queryForList(
                        "SELECT attempt_id,reservation_token FROM secret_validation_attempts WHERE"
                                + " job_id=? AND attempt_state IN('RESERVED','SENT') ORDER BY"
                                + " attempt_id DESC LIMIT 1",
                        job.jobId());
        if (rows.isEmpty()) {
            recordBlocked(job, c, method(c), "1", endpoint(c), result);
            return;
        }
        c.put("context_version", c.get("expected_context_version"));
        var a = rows.getFirst();
        complete(
                job,
                new Reservation(
                        num(a, "attempt_id"), c, a.get("reservation_token").toString(), null),
                result);
    }

    private Map<String, Object> findContext(
            ClaimedSecretJob job, SecretFindingNormalizer.Credential credential) {
        return findContext(job, credential, null);
    }

    private Map<String, Object> findContext(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            Long sourceRunScopeId) {
        return findContext(job, credential, sourceRunScopeId, null);
    }

    private Map<String, Object> findContext(
            ClaimedSecretJob job,
            SecretFindingNormalizer.Credential credential,
            Long sourceRunScopeId,
            String sourceRef) {
        if (credential == null) return null;
        boolean confirmed = "CONFIRMED".equals(credential.componentState());
        String identity = confirmed ? "k.fingerprint" : "k.candidate_locator";
        var rows =
                jdbc.queryForList(
                        """
SELECT v.*,o.source_object_ref,f.finding_id FROM secret_validation_context v JOIN secret_credential_sets k USING(credential_set_id)
JOIN secret_occurrences o USING(occurrence_id) JOIN secret_jobs j ON j.job_id=?
LEFT JOIN LATERAL(SELECT finding_id FROM secret_findings WHERE occurrence_id=v.occurrence_id ORDER BY detected_at DESC,finding_id DESC LIMIT 1) f ON true
WHERE v.connection_id=j.connection_id AND k.issuer=? AND k.credential_type=? AND k.component_state=? AND k.fingerprint_key_version=? AND
"""
                                + identity
                                + "=? AND (?::text IS NULL OR o.source_object_ref=?) AND"
                                + " ((j.purpose='CREDENTIAL_VALIDITY' AND"
                                + " v.occurrence_id=j.target_occurrence_id) OR"
                                + " (j.purpose<>'CREDENTIAL_VALIDITY' AND o.last_seen_run_id=?))"
                                + " AND EXISTS(SELECT 1 FROM secret_run_scopes sr JOIN"
                                + " secret_scan_runs rr USING(run_id) WHERE sr.run_id=? AND"
                                + " sr.scope_id=v.scope_id AND sr.scope_revision=v.scope_revision"
                                + " AND rr.scope_version=v.scope_version) AND (?::bigint IS NULL OR"
                                + " v.scope_id=(SELECT scope_id FROM secret_run_scopes WHERE"
                                + " run_scope_id=? AND run_id=?)) ORDER BY v.occurrence_id LIMIT 1",
                        job.jobId(),
                        credential.issuer(),
                        credential.credentialType(),
                        credential.componentState(),
                        credential.fingerprintKeyVersion(),
                        confirmed ? credential.fingerprint() : credential.candidateLocator(),
                        sourceRef,
                        sourceRef,
                        job.runId(),
                        job.runId(),
                        sourceRunScopeId,
                        sourceRunScopeId,
                        job.runId());
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private String preflight(Map<String, Object> c, boolean fixture, boolean enabled) {
        if (Boolean.TRUE.equals(c.get("synthetic_fixture"))) return "SYNTHETIC_FIXTURE";
        if (fixture || Boolean.TRUE.equals(c.get("source_guard_blocked")))
            return "SOURCE_GUARD_BLOCKED";
        if (!Set.of(
                        "AWS_ACCESS_KEY_PAIR",
                        "AWS_TEMPORARY_CREDENTIALS",
                        "GITHUB_CLASSIC_PAT",
                        "GITHUB_FINE_GRAINED_PAT",
                        "NOTION_CONNECTION_TOKEN")
                .contains(c.get("credential_type"))) return "UNSUPPORTED_TYPE";
        if (!enabled || !Boolean.TRUE.equals(c.get("validation_enabled"))) return "DISABLED";
        if (!"CONFIRMED".equals(c.get("component_state")))
            return "AWS_TEMPORARY_CREDENTIALS".equals(c.get("credential_type"))
                    ? "MISSING_SESSION_TOKEN"
                    : "INCOMPLETE_PAIR";
        if (!"ACTIVE".equals(c.get("connection_status"))
                || !Boolean.TRUE.equals(c.get("scope_enabled"))) return "SOURCE_UNAVAILABLE";
        if (!Boolean.TRUE.equals(c.get("validation_approved"))
                || !PROFILE.equals(c.get("connection_profile"))
                || !Objects.equals(c.get("connection_profile"), c.get("scope_profile")))
            return "NOT_APPROVED";
        return null;
    }

    private boolean recordBlocked(
            ClaimedSecretJob job,
            Map<String, Object> c,
            String validator,
            String version,
            String endpoint,
            CredentialValidationResult result) {
        var stored = new boolean[] {false};
        boolean fenced =
                jobs.persistIfLeased(
                        job.jobId(),
                        job.leaseToken(),
                        () -> {
                            var fresh = current(c);
                            if (fresh != null)
                                stored[0] =
                                        insert(
                                                        job,
                                                        fresh,
                                                        validator,
                                                        version,
                                                        endpoint,
                                                        cycle(job),
                                                        "COMPLETED",
                                                        result,
                                                        UUID.randomUUID().toString())
                                                > 0;
                        });
        return fenced && stored[0];
    }

    private Reservation reserve(
            ClaimedSecretJob job,
            Map<String, Object> c,
            String validator,
            String version,
            String endpoint) {
        var out = new AtomicReference<Reservation>(new Reservation(0, null, null, null));
        boolean live =
                jobs.persistIfLeased(
                        job.jobId(),
                        job.leaseToken(),
                        () -> {
                            jdbc.queryForObject(
                                    "SELECT pg_advisory_xact_lock(72525001)", Object.class);
                            abandonExpired();
                            var fresh = current(c);
                            if (fresh == null) return;
                            String cycle = cycle(job);
                            if (!Objects.equals(
                                    c.get("context_version"), fresh.get("context_version"))) {
                                var changed =
                                        CredentialValidationResult.unchecked("APPROVAL_CHANGED");
                                long stopped =
                                        insert(
                                                job,
                                                c,
                                                validator,
                                                version,
                                                endpoint,
                                                cycle,
                                                "COMPLETED",
                                                changed,
                                                UUID.randomUUID().toString());
                                jdbc.update(
                                        "UPDATE secret_validation_attempts SET"
                                            + " current_eligible=false,ineligible_reason_code='APPROVAL_CHANGED'"
                                            + " WHERE attempt_id=?",
                                        stopped);
                                out.set(new Reservation(0, c, null, changed));
                                return;
                            }
                            byte[] dedup = dedup(fresh, validator, version, cycle);
                            var done =
                                    jdbc.queryForList(
                                            "SELECT"
                                                + " result,reason_code,provider_checked_at,http_status,next_due_at"
                                                + " FROM secret_current_validation_attempts WHERE"
                                                + " credential_set_id=? AND validator_id=? AND"
                                                + " validator_version=? AND dedup_key=? AND result"
                                                + " IN('VALID','INVALID') AND (?::timestamptz IS"
                                                + " NULL OR provider_checked_at>?::timestamptz)"
                                                + " ORDER BY completed_at DESC LIMIT 1",
                                            num(fresh, "credential_set_id"),
                                            validator,
                                            version,
                                            dedup,
                                            fresh.get("action_performed_at"),
                                            fresh.get("action_performed_at"));
                            if (!done.isEmpty()) {
                                var d = done.getFirst();
                                out.set(
                                        new Reservation(
                                                0,
                                                fresh,
                                                null,
                                                new CredentialValidationResult(
                                                        (String) d.get("result"),
                                                        (String) d.get("reason_code"),
                                                        instant(d.get("provider_checked_at")),
                                                        (Integer) d.get("http_status"),
                                                        instant(d.get("next_due_at")))));
                                return;
                            }
                            var active =
                                    jdbc.queryForList(
                                            "SELECT"
                                                + " attempt_id,job_id,reservation_generation,reservation_token"
                                                + " FROM secret_validation_attempts WHERE"
                                                + " credential_set_id=? AND dedup_key=? AND"
                                                + " attempt_state IN('RESERVED','SENT')",
                                            num(fresh, "credential_set_id"),
                                            dedup);
                            if (!active.isEmpty()) {
                                var a = active.getFirst();
                                if (num(a, "job_id") == job.jobId()
                                        && num(a, "reservation_generation")
                                                == job.leaseGeneration())
                                    out.set(
                                            new Reservation(
                                                    num(a, "attempt_id"),
                                                    fresh,
                                                    a.get("reservation_token").toString(),
                                                    null));
                                return;
                            }
                            String token = UUID.randomUUID().toString();
                            long id =
                                    insert(
                                            job,
                                            fresh,
                                            validator,
                                            version,
                                            endpoint,
                                            cycle,
                                            "RESERVED",
                                            null,
                                            token);
                            out.set(new Reservation(id, fresh, token, null));
                        });
        if (!live) throw lease();
        return out.get();
    }

    /** Persists only a digest of the exact re-fetched version and protected source basis. */
    public void captureManualSource(ClaimedSecretJob job, String sourceRef, String sourceVersion) {
        var c = manualTarget(job);
        if (c == null || !Objects.equals(c.get("source_object_ref"), sourceRef))
            throw new IllegalArgumentException("SOURCE_IDENTITY_MISMATCH");
        var rows =
                jdbc.queryForList(
                        "SELECT attempt_id,reservation_token FROM secret_validation_attempts WHERE"
                                + " job_id=? AND attempt_state='RESERVED' ORDER BY attempt_id DESC"
                                + " LIMIT 1",
                        job.jobId());
        if (!rows.isEmpty()) {
            var a = rows.getFirst();
            captureSource(
                    job,
                    new Reservation(
                            num(a, "attempt_id"), c, a.get("reservation_token").toString(), null),
                    sourceRef,
                    sourceVersion);
        }
    }

    private void captureSource(
            ClaimedSecretJob job, Reservation reservation, String sourceRef, String version) {
        if (!jobs.persistIfLeased(
                job.jobId(),
                job.leaseToken(),
                () ->
                        jdbc.update(
                                "UPDATE secret_validation_attempts SET"
                                        + " source_object_version_digest=? WHERE attempt_id=? AND"
                                        + " reservation_token=?::uuid AND attempt_state='RESERVED'",
                                digest(
                                        "source-v1",
                                        sourceRef,
                                        version == null ? "VERSION_UNAVAILABLE" : version,
                                        reservation.context().get("scope_id"),
                                        reservation.context().get("scope_revision")),
                                reservation.id(),
                                reservation.token()))) throw lease();
    }

    private SendPermit sendPermit(ClaimedSecretJob job, Reservation reservation) {
        var issuedAt = new AtomicLong();
        var reason = new AtomicReference<CredentialValidationResult>();
        boolean live =
                jobs.persistIfLeased(
                        job.jobId(),
                        job.leaseToken(),
                        () -> {
                            jdbc.queryForObject(
                                    "SELECT pg_advisory_xact_lock(72525001)", Object.class);
                            var fresh = current(reservation.context());
                            if (fresh == null
                                    || !Objects.equals(
                                            fresh.get("context_version"),
                                            reservation.context().get("context_version"))
                                    || !requesterAllowed(job)
                                    || (isManual(job) && !targetCurrent(manualTarget(job)))) {
                                reason.set(
                                        CredentialValidationResult.unchecked("APPROVAL_CHANGED"));
                                return;
                            }
                            String pre = preflight(fresh, false, true);
                            if (pre != null) {
                                reason.set(CredentialValidationResult.unchecked(pre));
                                return;
                            }
                            String endpoint = endpoint(fresh);
                            var cooldown = jdbc.query(
                                    "SELECT reason_code,next_due_at FROM secret_validation_attempts"
                                            + " WHERE (credential_set_id=? OR endpoint_class IN('GITHUB_USER','NOTION_SELF'))"
                                            + " AND endpoint_class=?"
                                            + " AND (reason_code='RATE_LIMITED' OR"
                                            + " (reason_code='PROVIDER_UNAVAILABLE' AND http_status>=500))"
                                            + " AND next_due_at>clock_timestamp() AND attempt_id<>?"
                                            + " ORDER BY next_due_at DESC LIMIT 1",
                                    (rs, row) -> new CredentialValidationResult("UNCHECKED",
                                            rs.getString("reason_code"), null, null,
                                            rs.getObject("next_due_at", java.time.OffsetDateTime.class).toInstant()),
                                    num(fresh, "credential_set_id"), endpoint, reservation.id());
                            if (!cooldown.isEmpty()) {
                                reason.set(cooldown.getFirst());
                                return;
                            }
                            long minute =
                                    jdbc.queryForObject(
                                            "SELECT count(*) FROM secret_validation_attempts WHERE"
                                                + " endpoint_class=? AND"
                                                + " request_sent_at>clock_timestamp()-interval '1"
                                                + " minute' AND attempt_id<>?",
                                            Long.class,
                                            endpoint,
                                            reservation.id());
                            long active =
                                    jdbc.queryForObject(
                                            "SELECT count(*) FROM secret_validation_attempts WHERE"
                                                    + " attempt_state='SENT' AND attempt_id<>?",
                                            Long.class,
                                            reservation.id());
                            long run =
                                    jdbc.queryForObject(
                                            "SELECT count(*) FROM secret_validation_attempts WHERE"
                                                + " run_id=? AND request_sent_at IS NOT NULL AND"
                                                + " attempt_id<>?",
                                            Long.class,
                                            job.runId(),
                                            reservation.id());
                            long rejected =
                                    jdbc.queryForObject(
                                            "SELECT COALESCE(max(burst),0) FROM (SELECT count(*)"
                                                + " OVER(ORDER BY provider_checked_at RANGE BETWEEN"
                                                + " interval '60 seconds' PRECEDING AND CURRENT"
                                                + " ROW) AS burst FROM secret_validation_attempts"
                                                + " WHERE endpoint_class='GITHUB_USER' AND"
                                                + " reason_code='AUTHENTICATION_REJECTED' AND"
                                                + " provider_checked_at>clock_timestamp()-interval"
                                                + " '15 minutes') bursts",
                                            Long.class);
                            boolean deadline =
                                    Boolean.TRUE.equals(
                                            jdbc.queryForObject(
                                                    "SELECT started_at<clock_timestamp()-interval"
                                                            + " '30 minutes' FROM secret_scan_runs"
                                                            + " WHERE run_id=?",
                                                    Boolean.class,
                                                    job.runId()));
                            if (minute >= 30
                                    || active >= 2
                                    || run >= 500
                                    || deadline
                                    || "GITHUB_USER".equals(endpoint) && rejected >= 5) {
                                reason.set(
                                        new CredentialValidationResult(
                                                "UNCHECKED",
                                                "RATE_BUDGET_EXHAUSTED",
                                                null,
                                                null,
                                                Instant.now()
                                                        .plusSeconds(
                                                                "GITHUB_USER".equals(endpoint)
                                                                                && rejected >= 5
                                                                        ? 900
                                                                        : 60)));
                                return;
                            }
                            if (jdbc.update(
                                            "UPDATE secret_validation_attempts SET"
                                                + " attempt_state='SENT',request_sent_at=GREATEST(clock_timestamp(),requested_at)"
                                                + " WHERE attempt_id=? AND"
                                                + " reservation_token=?::uuid AND attempt_state"
                                                + " IN('RESERVED','SENT')",
                                            reservation.id(),
                                            reservation.token())
                                    != 1) throw lease();
                            issuedAt.set(System.nanoTime());
                        });
        if (!live) throw lease();
        return new SendPermit(reason.get(), issuedAt.get());
    }

    private void complete(ClaimedSecretJob job, Reservation r, CredentialValidationResult result) {
        boolean live =
                jobs.persistIfLeased(
                        job.jobId(),
                        job.leaseToken(),
                        () -> {
                            var fresh = current(r.context());
                            boolean eligible =
                                    fresh != null
                                            && Objects.equals(
                                                    fresh.get("context_version"),
                                                    r.context().get("context_version"))
                                            && requesterAllowed(job)
                                            && (!isManual(job) || targetCurrent(manualTarget(job)));
                            jdbc.update(
                                    """
UPDATE secret_validation_attempts SET attempt_state='COMPLETED',result=?,reason_code=?,
 provider_checked_at=CASE WHEN ?::timestamptz IS NULL THEN NULL ELSE GREATEST(?::timestamptz,request_sent_at) END,http_status=?,next_due_at=?,
 completed_at=greatest(clock_timestamp(),requested_at,request_sent_at,COALESCE(?::timestamptz,clock_timestamp())),current_eligible=?,ineligible_reason_code=?
WHERE attempt_id=? AND reservation_token=?::uuid AND attempt_state IN('RESERVED','SENT')
""",
                                    result.result(),
                                    result.reasonCode(),
                                    utc(result.providerCheckedAt()),
                                    utc(result.providerCheckedAt()),
                                    result.httpStatus(),
                                    utc(result.nextDueAt()),
                                    utc(result.providerCheckedAt()),
                                    eligible,
                                    eligible ? null : "APPROVAL_CHANGED",
                                    r.id(),
                                    r.token());
                            if(eligible&&"VALID".equals(result.result())&&result.identity()!=null){
                                var identity=result.identity();
                                jdbc.update("""
INSERT INTO secret_credential_identities(validation_attempt_id,occurrence_id,credential_set_id,credential_revision,scope_revision,provider,principal_type,account_ref,principal_ref,principal_id,safe_claims,observed_at,expires_at)
SELECT attempt_id,occurrence_id,credential_set_id,credential_revision,scope_revision,?,?,?,?,?,?::jsonb,provider_checked_at,provider_checked_at+interval '6 hours'
FROM secret_current_validation_attempts WHERE attempt_id=? AND result='VALID' AND current_eligible
ON CONFLICT(validation_attempt_id) DO NOTHING
""",identity.provider(),identity.principalType(),identity.accountRef(),identity.principalRef(),identity.principalId(),new tools.jackson.databind.json.JsonMapper().writeValueAsString(identity.claims()),r.id());
                            }
                        });
        if (!live) throw lease();
    }

    private long insert(
            ClaimedSecretJob job,
            Map<String, Object> c,
            String validator,
            String version,
            String endpoint,
            String cycle,
            String state,
            CredentialValidationResult result,
            String token) {
        boolean eligible =
                result != null
                        && requesterAllowed(job)
                        && (!isManual(job) || targetCurrent(manualTarget(job)));
        return jdbc.queryForObject(
                """
WITH validation_clock AS (SELECT clock_timestamp() AS at)
INSERT INTO secret_validation_attempts(evidence_version,credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,
 attempt_state,scope_id,occurrence_id,source_finding_id,source_object_version_digest,credential_revision,scope_revision,validation_revision,validation_approval_revision,
 validation_profile_version,action_context_digest,dedup_key,cycle_key,attempt_no,reservation_generation,reservation_token,
 result,reason_code,completed_at,current_eligible,ineligible_reason_code)
VALUES(1,?,?,?,?,?,?,(SELECT at FROM validation_clock),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?::uuid,?,?,CASE WHEN ?='COMPLETED' THEN (SELECT at FROM validation_clock) END,?,?) RETURNING attempt_id
""",
                Long.class,
                num(c, "credential_set_id"),
                job.runId(),
                job.jobId(),
                validator,
                version,
                endpoint,
                state,
                num(c, "scope_id"),
                num(c, "occurrence_id"),
                c.get("finding_id"),
                digest(
                        "protected-source-v1",
                        c.get("occurrence_id"),
                        c.get("scope_id"),
                        c.get("scope_revision"),
                        c.get("finding_id")),
                num(c, "credential_revision"),
                num(c, "scope_revision"),
                num(c, "validation_revision"),
                num(c, "validation_approval_revision"),
                c.get("connection_profile"),
                digest("action", c.get("action_id")),
                dedup(c, validator, version, cycle),
                cycle,
                job.attemptNo(),
                job.leaseGeneration(),
                token,
                result == null ? null : result.result(),
                result == null ? null : result.reasonCode(),
                state,
                eligible,
                result != null && !eligible ? "APPROVAL_CHANGED" : null);
    }

    private Map<String, Object> current(Map<String, Object> c) {
        var rows =
                jdbc.queryForList(
                        "SELECT v.*,o.source_object_ref,f.finding_id FROM secret_validation_context"
                            + " v JOIN secret_occurrences o USING(occurrence_id) LEFT JOIN"
                            + " LATERAL(SELECT finding_id FROM secret_findings WHERE"
                            + " occurrence_id=v.occurrence_id ORDER BY detected_at DESC,finding_id"
                            + " DESC LIMIT 1) f ON true WHERE v.occurrence_id=?",
                        num(c, "occurrence_id"));
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private boolean requesterAllowed(ClaimedSecretJob job) {
        return Boolean.TRUE.equals(
                jdbc.queryForObject(
                        """
SELECT (j.requested_by_user_id IS NULL OR EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=j.requested_by_user_id AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=j.connection_id) AND (g.role='SECURITY' OR (g.role='OPERATIONS' AND j.kind='FULL_SCAN') OR (g.role='REMEDIATOR' AND EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_response_cases c USING(case_id) WHERE co.occurrence_id=j.target_occurrence_id AND c.is_current AND (co.assigned_user_id=j.requested_by_user_id OR (co.assigned_user_id IS NULL AND EXISTS(SELECT 1 FROM secret_team_memberships tm WHERE tm.user_id=j.requested_by_user_id AND tm.removed_at IS NULL AND tm.team_name=co.assigned_team)))))))) FROM secret_jobs j WHERE j.job_id=?
""",
                        Boolean.class,
                        job.jobId()));
    }

    private String cycle(ClaimedSecretJob job) {
        return jdbc.queryForObject(
                "SELECT CASE WHEN purpose='CREDENTIAL_VALIDITY' THEN 'manual:'||job_id ELSE"
                        + " 'scheduled:'||floor(extract(epoch FROM scheduled_at)/21600)::bigint END"
                        + " FROM secret_jobs WHERE job_id=?",
                String.class,
                job.jobId());
    }

    private void abandonExpired() {
        jdbc.update(
                "UPDATE secret_validation_attempts a SET"
                    + " attempt_state='ABANDONED',reason_code='LEASE_EXPIRED',completed_at=GREATEST(clock_timestamp(),a.requested_at,a.request_sent_at),ineligible_reason_code='LEASE_EXPIRED'"
                    + " FROM secret_jobs j WHERE j.job_id=a.job_id AND a.attempt_state"
                    + " IN('RESERVED','SENT') AND (j.status<>'LEASED' OR"
                    + " j.lease_until<=clock_timestamp() OR"
                    + " j.lease_generation<>a.reservation_generation)");
    }

    private static String method(Map<String, Object> c) {
        return switch (Objects.toString(c.get("issuer"), "")) {
            case "AWS" -> "AWS_STS_GET_CALLER_IDENTITY";
            case "GITHUB" -> "GITHUB_GET_AUTHENTICATED_USER";
            case "NOTION" -> "NOTION_GET_SELF";
            default -> "UNSUPPORTED";
        };
    }

    private static String endpoint(Map<String, Object> c) {
        return switch (Objects.toString(c.get("issuer"), "")) {
            case "AWS" -> "AWS_STS";
            case "GITHUB" -> "GITHUB_USER";
            case "NOTION" -> "NOTION_SELF";
            default -> "UNSUPPORTED";
        };
    }

    private static byte[] dedup(
            Map<String, Object> c, String validator, String version, String cycle) {
        return digest(
                c.get("credential_set_id"),
                c.get("occurrence_id"),
                c.get("scope_id"),
                c.get("connection_id"),
                c.get("credential_revision"),
                c.get("fingerprint_key_version"),
                validator,
                version,
                c.get("validation_revision"),
                c.get("validation_approval_revision"),
                c.get("action_id"),
                c.get("action_performed_at"),
                cycle);
    }

    private static byte[] digest(Object... values) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(Arrays.deepToString(values).getBytes(StandardCharsets.UTF_8));
        } catch (Exception impossible) {
            throw new IllegalStateException("DIGEST_UNAVAILABLE");
        }
    }

    private static long num(Map<String, Object> c, String key) {
        return ((Number) c.get(key)).longValue();
    }

    private static Instant instant(Object o) {
        return o == null
                ? null
                : o instanceof OffsetDateTime d
                        ? d.toInstant()
                        : o instanceof java.sql.Timestamp t
                                ? t.toInstant()
                                : Instant.parse(o.toString());
    }

    private static OffsetDateTime utc(Instant i) {
        return i == null ? null : i.atOffset(ZoneOffset.UTC);
    }

    private static SecretJobFailure lease() {
        return new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
    }

    private static <T> T safely(Supplier<T> action) {
        try {
            return action.get();
        } catch (DataAccessException ignored) {
            String state =
                    ignored.getMostSpecificCause() instanceof java.sql.SQLException sql
                            ? sql.getSQLState()
                            : "UNKNOWN";
            var match =
                    java.util.regex.Pattern.compile("ck_secret_[a-z0-9_]{1,100}")
                            .matcher(
                                    Objects.toString(
                                            ignored.getMostSpecificCause().getMessage(), ""));
            String constraint = match.find() ? "_" + match.group() : "";
            throw new IllegalStateException("VALIDATION_PERSISTENCE_FAILED_" + state + constraint);
        }
    }

    private record SendPermit(CredentialValidationResult blocked, long issuedAtNanos) {}

    private record Reservation(
            long id,
            Map<String, Object> context,
            String token,
            CredentialValidationResult reused) {}
}
