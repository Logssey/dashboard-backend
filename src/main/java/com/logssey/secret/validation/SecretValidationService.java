package com.logssey.secret.validation;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;

/** Control plane only. No credential source or provider HTTP client is accessible here. */
@Service
public class SecretValidationService {
    public static final String PROFILE = "credential-validation-v1";
    private static final List<String> VALIDATION_ISSUERS = List.of("GITHUB", "AWS", "NOTION");
    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    private final SecretCommandExecutor commands;
    private final boolean awsEnabled, githubEnabled, notionEnabled, githubSourceEnabled, awsSourceEnabled;
    private final boolean notionSourceEnabled;

    public SecretValidationService(
            JdbcTemplate jdbc,
            SecretAccessService access,
            SecretCommandExecutor commands,
            @Value("${logssey.secret.validation.aws.enabled:false}") boolean awsEnabled,
            @Value("${logssey.secret.validation.github.enabled:false}") boolean githubEnabled) {
        this(jdbc, access, commands, awsEnabled, githubEnabled, true, true);
    }

    public SecretValidationService(
            JdbcTemplate jdbc,
            SecretAccessService access,
            SecretCommandExecutor commands,
            @Value("${logssey.secret.validation.aws.enabled:false}") boolean awsEnabled,
            @Value("${logssey.secret.validation.github.enabled:false}") boolean githubEnabled,
            @Value("${logssey.secret.github.enabled:false}") boolean githubSourceEnabled,
            @Value("${logssey.secret.aws.content.enabled:false}") boolean awsSourceEnabled) {
        this(jdbc, access, commands, awsEnabled, githubEnabled, false,
                githubSourceEnabled, awsSourceEnabled);
    }

    public SecretValidationService(
            JdbcTemplate jdbc,
            SecretAccessService access,
            SecretCommandExecutor commands,
            @Value("${logssey.secret.validation.aws.enabled:false}") boolean awsEnabled,
            @Value("${logssey.secret.validation.github.enabled:false}") boolean githubEnabled,
            @Value("${logssey.secret.validation.notion.enabled:false}") boolean notionEnabled,
            @Value("${logssey.secret.github.enabled:false}") boolean githubSourceEnabled,
            @Value("${logssey.secret.aws.content.enabled:false}") boolean awsSourceEnabled) {
        this(jdbc, access, commands, awsEnabled, githubEnabled, notionEnabled,
                githubSourceEnabled, awsSourceEnabled, false);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SecretValidationService(
            JdbcTemplate jdbc, SecretAccessService access, SecretCommandExecutor commands,
            @Value("${logssey.secret.validation.aws.enabled:false}") boolean awsEnabled,
            @Value("${logssey.secret.validation.github.enabled:false}") boolean githubEnabled,
            @Value("${logssey.secret.validation.notion.enabled:false}") boolean notionEnabled,
            @Value("${logssey.secret.github.enabled:false}") boolean githubSourceEnabled,
            @Value("${logssey.secret.aws.content.enabled:false}") boolean awsSourceEnabled,
            @Value("${logssey.secret.notion.collection.enabled:false}") boolean notionSourceEnabled) {
        this.githubSourceEnabled = githubSourceEnabled;
        this.awsSourceEnabled = awsSourceEnabled;
        this.jdbc = jdbc;
        this.access = access;
        this.commands = commands;
        this.awsEnabled = awsEnabled;
        this.githubEnabled = githubEnabled;
        this.notionEnabled = notionEnabled;
        this.notionSourceEnabled = notionSourceEnabled;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> read(long key, Long occurrence, String login) {
        var actor = access.requirePrincipal(login);
        var c = context(key, occurrence, actor);
        long oid = num(c, "occurrence_id");
        var completed = attempts(c, false, 0, 100);
        var latest = completed.isEmpty() ? null : completed.getFirst();
        var conclusive =
                attempts(c, false, 0, 1, "a.result IN('VALID','INVALID')").stream()
                        .findFirst()
                        .orElse(null);
        var auth = attempts(c, false, 0, 1, "a.result='VALID'").stream().findFirst().orElse(null);
        Instant now = Instant.now(),
                observed = conclusive == null ? null : instant(conclusive.get("providerCheckedAt"));
        Instant due = observed == null ? null : observed.plus(Duration.ofHours(6));
        Instant action = instant(c.get("action_performed_at"));
        boolean post = action != null && (observed == null || !observed.isAfter(action));
        var blocked = blocked(c);
        if (!canRequest(actor, c)) blocked.add("NOT_AUTHORIZED");
        if (hasActiveJob(c)) blocked.add("ACTIVE_JOB_EXISTS");
        if (requestBudgetExceeded(actor)) blocked.add("RATE_BUDGET_EXHAUSTED");
        String freshness =
                observed == null
                        ? "UNAVAILABLE"
                        : post
                                ? "POST_ACTION_REQUIRED"
                                : latest != null
                                                && !Set.of("VALID", "INVALID")
                                                        .contains(latest.get("result"))
                                        ? "UNAVAILABLE"
                                        : !now.isBefore(due) ? "STALE" : "CURRENT";
        var result = new LinkedHashMap<String, Object>();
        result.put(
                "support",
                Map.of(
                        "status",
                        supported(c) ? "SUPPORTED" : "UNSUPPORTED",
                        "reasonCode",
                        supported(c) ? "SUPPORTED" : "UNSUPPORTED_TYPE",
                        "methods",
                        supported(c) ? List.of(method(c)) : List.of()));
        result.put("latestAttempt", latest);
        result.put("lastAuthenticatedAt", auth == null ? null : auth.get("providerCheckedAt"));
        result.put("lastConclusiveValidation", conclusive);
        result.put("latestRequest", latestRequest(oid));
        result.put(
                "freshness",
                nullable(
                        "status",
                        freshness,
                        "reasonCodes",
                        List.of(
                                freshness.equals("CURRENT")
                                        ? "WITHIN_CHECK_PERIOD"
                                        : post
                                                ? "POST_ACTION_VALIDATION_REQUIRED"
                                                : freshness.equals("STALE")
                                                        ? "CHECK_PERIOD_EXCEEDED"
                                                        : "NO_CURRENT_CONCLUSIVE_RESULT"),
                        "checkDueAt",
                        due));
        // Observation freshness is independent of whether a retry is actually queued.
        result.put("nextDueAt", due);
        result.put("postActionValidationPending", post);
        result.put(
                "capabilities",
                Map.of("canRequestValidation", blocked.isEmpty(), "blockedReasonCodes", blocked));
        result.put("validationPolicy", policyFor(c, actor));
        result.put("readAt", now);
        result.put("contextVersion", c.get("context_version"));
        result.put("coverage", Map.of("occurrenceId", oid, "unit", "SELECTED_OCCURRENCE"));
        result.put(
                "limitations", List.of("AUTHENTICATION_ONLY", "NO_PERMISSION_OR_REVOCATION_PROOF"));
        return result;
    }

    public Map<String, Object> request(long key, Map<String, Object> body, String login) {
        exact(body, Set.of("occurrenceId", "expectedContextVersion", "idempotencyKey"));
        long oid = positive(body.get("occurrenceId"));
        String expected = token(body.get("expectedContextVersion"), "[a-f0-9]{64}");
        String idem = token(body.get("idempotencyKey"), "[A-Za-z0-9._:-]{1,120}");
        var actor = access.requirePrincipal(login);
        var replay = new boolean[] {false};
        var executed = new boolean[] {false};
        var result =
                commands.execute(
                        actor,
                        SecretCommandExecutor.Kind.CREDENTIAL_VALIDATION,
                        idem,
                        digest(key, oid, expected),
                        () -> {
                            var c = context(key, oid, actor);
                            if (!canRequest(actor, c))
                                throw fail(ErrorCode.FORBIDDEN, "NOT_AUTHORIZED");
                        },
                        () -> {
                            executed[0] = true;
                            var c = context(key, oid, actor);
                            jdbc.queryForObject(
                                    "SELECT connection_id FROM secret_connections WHERE"
                                            + " connection_id=? FOR UPDATE",
                                    Long.class,
                                    num(c, "connection_id"));
                            c = context(key, oid, actor);
                            if (!expected.equals(c.get("context_version")))
                                throw fail(ErrorCode.CONFLICT, "CONTEXT_CHANGED");
                            var active =
                                    jdbc.queryForList(
                                            "SELECT job_id,purpose,target_occurrence_id FROM"
                                                    + " secret_jobs WHERE connection_id=? AND kind"
                                                    + " IN('FULL_SCAN','REVALIDATE') AND status"
                                                    + " IN('PENDING','LEASED')",
                                            num(c, "connection_id"));
                            if (!active.isEmpty()) {
                                var prior = active.getFirst();
                                if ("CREDENTIAL_VALIDITY".equals(prior.get("purpose"))
                                        && Objects.equals(prior.get("target_occurrence_id"), oid)) {
                                    replay[0] = true;
                                    return new SecretCommandResult(
                                            num(prior, "job_id"),
                                            0,
                                            SecretCommandResult.Status.PENDING);
                                }
                                throw fail(ErrorCode.CONFLICT, "ACTIVE_JOB_EXISTS");
                            }
                            var reasons = blocked(c);
                            if (!reasons.isEmpty())
                                throw fail(ErrorCode.UNPROCESSABLE, reasons.getFirst());
                            jdbc.queryForObject(
                                    "SELECT pg_advisory_xact_lock(72525002,?::int)",
                                    Object.class,
                                    Math.floorMod(actor.userId(), Integer.MAX_VALUE));
                            long requests =
                                    jdbc.queryForObject(
                                            "SELECT count(*) FROM secret_jobs WHERE"
                                                    + " purpose='CREDENTIAL_VALIDITY' AND"
                                                    + " requested_by_user_id=? AND"
                                                    + " created_at>clock_timestamp()-interval '1"
                                                    + " minute'",
                                            Long.class,
                                            actor.userId());
                            if (requests >= 10) throw new ValidationRateLimitException();
                            long job =
                                    jdbc.queryForObject(
                                            """
INSERT INTO secret_jobs(kind,purpose,connection_id,target_occurrence_id,requested_by_user_id,idempotency_key,expected_context,
 scheduled_at,available_at,attempt_no,max_attempts,status)
VALUES('REVALIDATE','CREDENTIAL_VALIDITY',?,?,?, ?,jsonb_build_object('contextVersion',?::text,'credentialRevision',?::bigint,'scopeId',?::bigint,'scopeRevision',?::bigint,'validationRevision',?::bigint,'validationApprovalRevision',?::bigint,'profileVersion',?::text,'actionId',?::bigint,'occurrenceRevision',?::bigint,'validatorVersion','1'),clock_timestamp(),
 GREATEST(clock_timestamp(),(SELECT max(retry.source_retry_at) FROM secret_connections source
 JOIN secret_connections retry ON retry.provider='NOTION' AND retry.auth_ref=source.auth_ref
 WHERE source.connection_id=? AND source.provider='NOTION')),0,3,'PENDING') RETURNING job_id
""",
                                            Long.class,
                                            num(c, "connection_id"),
                                            oid,
                                            actor.userId(),
                                            "validation:" + UUID.randomUUID(),
                                            expected,
                                            num(c, "credential_revision"),
                                            num(c, "scope_id"),
                                            num(c, "scope_revision"),
                                            num(c, "validation_revision"),
                                            num(c, "validation_approval_revision"),
                                            c.get("connection_profile"),
                                            num(c, "action_id"),
                                            num(c, "occurrence_revision"),
                                            num(c, "connection_id"));
                            long run =
                                    jdbc.queryForObject(
                                            """
INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status)
VALUES(?,?,'REVALIDATION',?,clock_timestamp(),clock_timestamp(),'PENDING','PENDING','PENDING','PENDING') RETURNING run_id
""",
                                            Long.class,
                                            job,
                                            num(c, "connection_id"),
                                            num(c, "scope_version"));
                            jdbc.update(
                                    "INSERT INTO"
                                        + " secret_run_scopes(run_id,scope_id,collection_status)"
                                        + " VALUES(?,?,'PENDING')",
                                    run,
                                    num(c, "scope_id"));
                            return new SecretCommandResult(
                                    job, 0, SecretCommandResult.Status.PENDING);
                        });
        var status = requestStatus(result.targetId(), login);
        status.put("reused", replay[0] || !executed[0]);
        status.put("requiresSnapshotRefresh", true);
        return status;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> requestStatus(long id, String login) {
        var actor = access.requirePrincipal(login);
        var rows =
                jdbc.queryForList(
                        """
                        SELECT j.job_id,j.target_occurrence_id,j.status,j.created_at,
                         CASE WHEN j.status='PENDING' THEN GREATEST(j.available_at,(
                          SELECT max(retry.source_retry_at) FROM secret_connections source
                          JOIN secret_connections retry ON retry.provider='NOTION' AND retry.auth_ref=source.auth_ref
                          WHERE source.connection_id=j.connection_id AND source.provider='NOTION'
                         )) ELSE j.available_at END AS available_at,
                         j.finished_at,j.last_error_code,j.attempt_no,j.max_attempts,r.run_id,r.started_at
                        """
                            + " FROM secret_jobs j JOIN secret_scan_runs r ON r.job_id=j.job_id"
                            + " WHERE j.job_id=? AND j.purpose='CREDENTIAL_VALIDITY'",
                        id);
        if (rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
        var row = rows.getFirst();
        access.requireOccurrenceRead(actor, num(row, "target_occurrence_id"));
        return nullable(
                "requestId",
                id,
                "jobId",
                id,
                "runId",
                row.get("run_id"),
                "status",
                row.get("status"),
                "requestedAt",
                row.get("created_at"),
                "scheduledAt",
                row.get("available_at"),
                "startedAt",
                row.get("started_at"),
                "completedAt",
                row.get("finished_at"),
                "attemptNo",
                row.get("attempt_no"),
                "maxAttempts",
                row.get("max_attempts"),
                "availableAt",
                "PENDING".equals(row.get("status")) ? row.get("available_at") : null,
                "nextRetryAt",
                "PENDING".equals(row.get("status")) && num(row, "attempt_no") > 0
                        ? row.get("available_at") : null,
                "reasonCode",
                row.get("last_error_code"));
    }

    @Transactional(readOnly = true)
    public Map<String, Object> history(long key, Long oid, int page, int size, String login) {
        if (page < 0 || size < 1 || size > 100) throw new ApiException(ErrorCode.INVALID_INPUT);
        var c = context(key, oid, access.requirePrincipal(login));
        long total =
                jdbc.queryForObject(
                        "SELECT count(*) FROM secret_validation_attempts WHERE credential_set_id=?"
                            + " AND occurrence_id=? AND attempt_state IN('COMPLETED','ABANDONED')",
                        Long.class,
                        key,
                        num(c, "occurrence_id"));
        return Map.of(
                "items",
                attempts(c, true, page * size, size),
                "total",
                total,
                "page",
                page,
                "size",
                size,
                "unit",
                "ValidationAttempt");
    }

    @Transactional(readOnly = true)
    public Map<String, Object> policy(long scope, String login) {
        var actor = access.requirePrincipal(login);
        var rows =
                jdbc.queryForList(
                        "SELECT"
                            + " s.scope_id,s.connection_id,c.validation_enabled,c.validation_profile_version"
                            + " AS connection_profile,c.validation_allowed_issuers,s.validation_approved,s.validation_approval_revision,s.validation_profile_version"
                            + " AS scope_profile FROM secret_connection_scopes s JOIN"
                            + " secret_connections c USING(connection_id) WHERE s.scope_id=?",
                        scope);
        if (rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
        var c = rows.getFirst();
        access.requireConnectionFactsRead(actor, num(c, "connection_id"));
        return policyFor(c, actor);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> connectionPolicy(long connection, String login) {
        var actor = access.requirePrincipal(login);
        var c = connectionPolicyRow(connection, false);
        access.requireConnectionFactsRead(actor, connection);
        boolean canConfigure = access.hasConnectionRole(actor, connection, SecretRole.SECURITY);
        var allowed = allowedIssuers(c.get("validation_allowed_issuers"));
        var enabledIssuers = VALIDATION_ISSUERS.stream().filter(this::issuerEnabled).toList();
        var reasons = new ArrayList<String>();
        if (!canConfigure) reasons.add("SECURITY_REQUIRED");
        if (!PROFILE.equals(c.get("validation_profile_version"))) reasons.add("PROFILE_UNCONFIGURED");
        if (!Boolean.TRUE.equals(c.get("validation_enabled"))) reasons.add("DISABLED");
        if (allowed.stream().anyMatch(issuer -> !enabledIssuers.contains(issuer)))
            reasons.add("VALIDATOR_DISABLED");
        var counts = jdbc.queryForMap("""
                SELECT count(*) FILTER(WHERE enabled) AS scope_count,
                  count(*) FILTER(WHERE enabled AND validation_approved) AS approved_scope_count
                FROM secret_connection_scopes WHERE connection_id=?
                """, connection);
        return Map.ofEntries(
                Map.entry("connectionId", connection), Map.entry("provider", c.get("provider")),
                Map.entry("enabled", Boolean.TRUE.equals(c.get("validation_enabled"))),
                Map.entry("allowedIssuers", allowed),
                Map.entry("enabledIssuers", enabledIssuers),
                Map.entry("expectedValidationRevision", num(c, "validation_revision")),
                Map.entry("profileStatus", !PROFILE.equals(c.get("validation_profile_version"))
                        ? "UNCONFIGURED" : Boolean.TRUE.equals(c.get("validation_enabled"))
                                && allowed.stream().anyMatch(enabledIssuers::contains) ? "ENABLED" : "DISABLED"),
                Map.entry("canConfigure", canConfigure), Map.entry("blockedReasonCodes", reasons),
                Map.entry("scopeCount", num(counts, "scope_count")),
                Map.entry("approvedScopeCount", num(counts, "approved_scope_count")));
    }

    public Map<String, Object> updateConnectionPolicy(long connection, Map<String, Object> body, String login) {
        exact(body, Set.of("expectedValidationRevision", "idempotencyKey", "enabled", "allowedIssuers", "reasonCode"));
        long revision = positive(body.get("expectedValidationRevision"));
        String idem = token(body.get("idempotencyKey"), "[A-Za-z0-9._:-]{1,120}");
        if (!(body.get("enabled") instanceof Boolean enabled)) throw new ApiException(ErrorCode.INVALID_INPUT);
        var issuers = requestedIssuers(body.get("allowedIssuers"));
        if (enabled && issuers.isEmpty()) throw new ApiException(ErrorCode.INVALID_INPUT);
        String reason = token(body.get("reasonCode"), "VALIDATION_APPROVED|VALIDATION_DISABLED");
        if (!(enabled ? "VALIDATION_APPROVED" : "VALIDATION_DISABLED").equals(reason))
            throw new ApiException(ErrorCode.INVALID_INPUT);
        var actor = access.requirePrincipal(login);
        commands.execute(actor, SecretCommandExecutor.Kind.CONNECTION_VALIDATION_POLICY, idem,
                digest(connection, revision, enabled, issuers, reason),
                () -> {
                    connectionPolicyRow(connection, false);
                    if (!access.hasConnectionRole(actor, connection, SecretRole.SECURITY))
                        throw new ApiException(ErrorCode.FORBIDDEN);
                }, () -> {
                    var c = connectionPolicyRow(connection, true);
                    if (num(c, "validation_revision") != revision)
                        throw fail(ErrorCode.CONFLICT, "CONTEXT_CHANGED");
                    jdbc.update("""
                            UPDATE secret_connections SET validation_enabled=?,validation_profile_version=?,
                              validation_allowed_issuers=string_to_array(?,','),validation_revision=validation_revision+1
                            WHERE connection_id=?
                            """, enabled, PROFILE, String.join(",", issuers), connection);
                    jdbc.update("""
                            UPDATE secret_validation_attempts SET current_eligible=false,ineligible_reason_code='APPROVAL_CHANGED'
                            WHERE scope_id IN(SELECT scope_id FROM secret_connection_scopes WHERE connection_id=?)
                              AND current_eligible
                            """, connection);
                    jdbc.update("""
                            UPDATE secret_jobs SET status='CANCELLED',last_error_code='APPROVAL_CHANGED',finished_at=clock_timestamp()
                            WHERE connection_id=? AND purpose='CREDENTIAL_VALIDITY' AND status='PENDING'
                            """, connection);
                    return new SecretCommandResult(connection, revision + 1, SecretCommandResult.Status.SUCCEEDED);
                });
        var result = new LinkedHashMap<>(connectionPolicy(connection, login));
        result.put("requiresSnapshotRefresh", true);
        return result;
    }

    private Map<String, Object> connectionPolicyRow(long connection, boolean lock) {
        if (connection <= 0) throw new ApiException(ErrorCode.NOT_FOUND);
        var rows = jdbc.queryForList("""
                SELECT connection_id,provider,validation_enabled,validation_profile_version,
                  validation_allowed_issuers,validation_revision FROM secret_connections WHERE connection_id=?
                """ + (lock ? " FOR UPDATE" : ""), connection);
        if (rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
        return rows.getFirst();
    }

    private List<String> requestedIssuers(Object value) {
        if (!(value instanceof List<?> values) || values.size() > VALIDATION_ISSUERS.size()
                || values.stream().anyMatch(item -> !(item instanceof String) || !VALIDATION_ISSUERS.contains(item))
                || new HashSet<>(values).size() != values.size()) throw new ApiException(ErrorCode.INVALID_INPUT);
        return VALIDATION_ISSUERS.stream().filter(values::contains).toList();
    }

    private List<String> allowedIssuers(Object value) {
        if (value instanceof java.sql.Array array) {
            try { return Arrays.asList((String[]) array.getArray()); }
            catch (java.sql.SQLException failure) { throw new IllegalStateException("VALIDATION_POLICY_UNAVAILABLE"); }
        }
        if (value instanceof String[] values) return Arrays.asList(values);
        return List.of();
    }

    private boolean issuerEnabled(String issuer) {
        return switch (issuer) {
            case "GITHUB" -> githubEnabled;
            case "AWS" -> awsEnabled;
            case "NOTION" -> notionEnabled;
            default -> false;
        };
    }

    public Map<String, Object> updatePolicy(long scope, Map<String, Object> body, String login) {
        exact(
                body,
                Set.of(
                        "expectedValidationApprovalRevision",
                        "idempotencyKey",
                        "enabled",
                        "reasonCode"));
        long rev = positive(body.get("expectedValidationApprovalRevision"));
        String idem = token(body.get("idempotencyKey"), "[A-Za-z0-9._:-]{1,120}");
        String reason =
                token(
                        body.get("reasonCode"),
                        "VALIDATION_APPROVED|VALIDATION_DISABLED|ENABLE_VALIDATION|DISABLE_VALIDATION|APPROVED_SCOPE|POLICY_CHANGE");
        if (!(body.get("enabled") instanceof Boolean))
            throw new ApiException(ErrorCode.INVALID_INPUT);
        boolean enabled = (Boolean) body.get("enabled");
        var actor = access.requirePrincipal(login);
        commands.execute(
                actor,
                SecretCommandExecutor.Kind.VALIDATION_POLICY,
                idem,
                digest(scope, rev, enabled, reason),
                () -> {
                    var p = policy(scope, login);
                    if (!Boolean.TRUE.equals(p.get("canConfigure")))
                        throw new ApiException(ErrorCode.FORBIDDEN);
                },
                () -> {
                    var rows =
                            jdbc.queryForList(
                                    "SELECT"
                                        + " s.connection_id,s.validation_approval_revision,c.validation_profile_version"
                                        + " FROM secret_connection_scopes s JOIN secret_connections"
                                        + " c USING(connection_id) WHERE scope_id=? FOR UPDATE OF"
                                        + " s,c",
                                    scope);
                    if (rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
                    var c = rows.getFirst();
                    if (num(c, "validation_approval_revision") != rev)
                        throw fail(ErrorCode.CONFLICT, "CONTEXT_CHANGED");
                    if (enabled && !PROFILE.equals(c.get("validation_profile_version")))
                        throw fail(ErrorCode.UNPROCESSABLE, "PROFILE_UNCONFIGURED");
                    jdbc.update(
                            "UPDATE secret_connection_scopes SET"
                                + " validation_approved=?,validation_approval_revision=validation_approval_revision+1,validation_profile_version=?,validation_approved_by_user_id=?,validation_approved_at=clock_timestamp()"
                                + " WHERE scope_id=?",
                            enabled,
                            c.get("validation_profile_version"),
                            actor.userId(),
                            scope);
                    jdbc.update(
                            "UPDATE secret_validation_attempts SET"
                                + " current_eligible=false,ineligible_reason_code='APPROVAL_CHANGED'"
                                + " WHERE scope_id=? AND current_eligible",
                            scope);
                    jdbc.update(
                            "UPDATE secret_jobs SET"
                                + " status='CANCELLED',last_error_code='APPROVAL_CHANGED',finished_at=clock_timestamp()"
                                + " WHERE purpose='CREDENTIAL_VALIDITY' AND status='PENDING' AND"
                                + " target_occurrence_id IN(SELECT occurrence_id FROM"
                                + " secret_occurrences WHERE scope_id=?)",
                            scope);
                    return new SecretCommandResult(
                            scope, rev + 1, SecretCommandResult.Status.SUCCEEDED);
                });
        return policy(scope, login);
    }

    private Map<String, Object> context(long key, Long oid, SecretPrincipal actor) {
        if (key <= 0 || oid != null && oid <= 0) throw new ApiException(ErrorCode.NOT_FOUND);
        var rows =
                jdbc.queryForList(
                        "SELECT v.*,s.content_type,s.approved_ref,s.history_limit,source.auth_ref AS source_auth_ref"
                                + " FROM secret_validation_context v JOIN secret_connection_scopes s USING(scope_id)"
                                + " JOIN secret_connections source ON source.connection_id=v.connection_id WHERE"
                                + " credential_set_id=? AND (?::bigint IS NULL OR occurrence_id=?)"
                                + " ORDER BY occurrence_id",
                        key,
                        oid,
                        oid);
        return rows.stream()
                .filter(c -> access.canReadOccurrence(actor, num(c, "occurrence_id")))
                .findFirst()
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    private List<String> blocked(Map<String, Object> c) {
        var reasons = new ArrayList<String>();
        if (!supported(c)) reasons.add("UNSUPPORTED_TYPE");
        if (!sourceSupported(c)) reasons.add("UNSUPPORTED_SOURCE");
        else if (!(switch (Objects.toString(c.get("source_provider"), "")) {
            case "GITHUB" -> githubSourceEnabled;
            case "AWS" -> awsSourceEnabled;
            case "NOTION" -> notionSourceEnabled
                    && com.logssey.secret.notion.SecretNotionSourceCredentials.isReference((String)c.get("source_auth_ref"));
            default -> false;
        })) reasons.add("SOURCE_UNAVAILABLE");
        if (!"CONFIRMED".equals(c.get("component_state"))) reasons.add("INCOMPLETE_PAIR");
        if (Boolean.TRUE.equals(c.get("synthetic_fixture"))) reasons.add("SYNTHETIC_FIXTURE");
        if (Boolean.TRUE.equals(c.get("source_guard_blocked"))) reasons.add("SOURCE_GUARD_BLOCKED");
        if (!Boolean.TRUE.equals(c.get("validation_issuer_allowed"))) reasons.add("VALIDATOR_NOT_ALLOWED");
        if (!global(c) || !Boolean.TRUE.equals(c.get("validation_enabled")))
            reasons.add("DISABLED");
        if (!PROFILE.equals(c.get("connection_profile"))) reasons.add("PROFILE_UNCONFIGURED");
        if (!Boolean.TRUE.equals(c.get("validation_approved"))
                || !Objects.equals(c.get("connection_profile"), c.get("scope_profile")))
            reasons.add("NOT_APPROVED");
        if (!"ACTIVE".equals(c.get("connection_status"))
                || !Boolean.TRUE.equals(c.get("scope_enabled"))) reasons.add("SOURCE_UNAVAILABLE");
        return reasons;
    }

    private List<String> policyBlocks(Map<String, Object> c, boolean configure) {
        var reasons = new ArrayList<String>();
        if (!configure) reasons.add("SECURITY_REQUIRED");
        if (!PROFILE.equals(c.get("connection_profile"))) reasons.add("PROFILE_UNCONFIGURED");
        if (!Boolean.TRUE.equals(c.get("validation_enabled"))
                || allowedIssuers(c.get("validation_allowed_issuers")).stream().noneMatch(this::issuerEnabled))
            reasons.add("DISABLED");
        return reasons;
    }

    private boolean sourceSupported(Map<String, Object> c) {
        if ("NOTION".equals(c.get("source_provider")))
            return com.logssey.secret.notion.NotionScopeSql.valid((String)c.get("content_type"),
                    (String)c.get("approved_ref"),(String)c.get("history_limit"));
        return "GITHUB".equals(c.get("source_provider"))
                ? "GITHUB_REPOSITORY_FILES".equals(c.get("content_type"))
                : "AWS".equals(c.get("source_provider"))
                        && Set.of(
                                        "AWS_SECRETS_MANAGER_VALUE",
                                        "AWS_SSM_PARAMETER_VALUE",
                                        "AWS_S3_OBJECT_CONTENT")
                                .contains(c.get("content_type"));
    }

    private boolean hasActiveJob(Map<String, Object> c) {
        return Boolean.TRUE.equals(
                jdbc.queryForObject(
                        "SELECT EXISTS(SELECT 1 FROM secret_jobs WHERE connection_id=? AND kind"
                            + " IN('FULL_SCAN','REVALIDATE') AND status IN('PENDING','LEASED'))",
                        Boolean.class,
                        num(c, "connection_id")));
    }

    private boolean requestBudgetExceeded(SecretPrincipal actor) {
        return jdbc.queryForObject(
                        "SELECT count(*) FROM secret_jobs WHERE purpose='CREDENTIAL_VALIDITY' AND"
                            + " requested_by_user_id=? AND created_at>clock_timestamp()-interval '1"
                            + " minute'",
                        Long.class,
                        actor.userId())
                >= 10;
    }

    private boolean global(Map<String, Object> c) {
        return switch (Objects.toString(c.get("issuer"), "")) {
            case "AWS" -> awsEnabled;
            case "GITHUB" -> githubEnabled;
            case "NOTION" -> notionEnabled;
            default -> false;
        };
    }

    private boolean canRequest(SecretPrincipal actor, Map<String, Object> c) {
        return access.hasConnectionRole(actor, num(c, "connection_id"), SecretRole.SECURITY)
                || (access.hasConnectionRole(actor, num(c, "connection_id"), SecretRole.REMEDIATOR)
                        && access.canReadOccurrence(actor, num(c, "occurrence_id")));
    }

    private boolean supported(Map<String, Object> c) {
        return switch (Objects.toString(c.get("issuer"), "")) {
            case "AWS" -> Set.of("AWS_ACCESS_KEY_PAIR", "AWS_TEMPORARY_CREDENTIALS")
                    .contains(c.get("credential_type"));
            case "GITHUB" -> Set.of("GITHUB_CLASSIC_PAT", "GITHUB_FINE_GRAINED_PAT")
                    .contains(c.get("credential_type"));
            case "NOTION" -> "NOTION_CONNECTION_TOKEN".equals(c.get("credential_type"));
            default -> false;
        };
    }

    private String method(Map<String, Object> c) {
        return switch (Objects.toString(c.get("issuer"), "")) {
            case "AWS" -> "AWS_STS_GET_CALLER_IDENTITY";
            case "GITHUB" -> "GITHUB_GET_AUTHENTICATED_USER";
            case "NOTION" -> "NOTION_GET_SELF";
            default -> throw new IllegalArgumentException("UNSUPPORTED_VALIDATION_ISSUER");
        };
    }

    private Map<String, Object> policyFor(Map<String, Object> c, SecretPrincipal actor) {
        boolean configure =
                access.hasConnectionRole(actor, num(c, "connection_id"), SecretRole.SECURITY);
        var result = new LinkedHashMap<String, Object>();
        result.put("connectionId", num(c, "connection_id"));
        result.put("connectionEnabled", Boolean.TRUE.equals(c.get("validation_enabled")));
        result.put("allowedIssuers", allowedIssuers(c.get("validation_allowed_issuers")));
        result.put("expectedValidationApprovalRevision", num(c, "validation_approval_revision"));
        result.put("enabled", Boolean.TRUE.equals(c.get("validation_approved")));
        result.put("profileStatus", !PROFILE.equals(c.get("connection_profile"))
                ? "UNCONFIGURED" : Boolean.TRUE.equals(c.get("validation_enabled"))
                        && allowedIssuers(c.get("validation_allowed_issuers")).stream().anyMatch(this::issuerEnabled)
                        ? "ENABLED" : "DISABLED");
        result.put("canConfigure", configure);
        result.put("blockedReasonCodes", policyBlocks(c, configure));
        return result;
    }

    private Map<String, Object> latestRequest(long oid) {
        var list =
                jdbc.queryForList(
                        """
                        SELECT j.job_id,j.status,j.created_at,
                         CASE WHEN j.status='PENDING' THEN GREATEST(j.available_at,(
                          SELECT max(retry.source_retry_at) FROM secret_connections source
                          JOIN secret_connections retry ON retry.provider='NOTION' AND retry.auth_ref=source.auth_ref
                          WHERE source.connection_id=j.connection_id AND source.provider='NOTION'
                         )) ELSE j.available_at END AS available_at,
                         j.finished_at,j.attempt_no,j.max_attempts,j.last_error_code FROM secret_jobs j WHERE
                        """
                            + " target_occurrence_id=? AND purpose='CREDENTIAL_VALIDITY'"
                            + " ORDER BY job_id DESC LIMIT 1",
                        oid);
        return list.isEmpty()
                ? null
                : nullable(
                        "requestId",
                        num(list.getFirst(), "job_id"),
                        "status",
                        list.getFirst().get("status"),
                        "requestedAt",
                        list.getFirst().get("created_at"),
                        "scheduledAt",
                        list.getFirst().get("available_at"),
                        "completedAt",
                        list.getFirst().get("finished_at"),
                        "attemptNo",
                        list.getFirst().get("attempt_no"),
                        "maxAttempts",
                        list.getFirst().get("max_attempts"),
                        "availableAt",
                        "PENDING".equals(list.getFirst().get("status"))
                                ? list.getFirst().get("available_at") : null,
                        "nextRetryAt",
                        "PENDING".equals(list.getFirst().get("status"))
                                        && num(list.getFirst(), "attempt_no") > 0
                                ? list.getFirst().get("available_at") : null,
                        "reasonCode",
                        list.getFirst().get("last_error_code"));
    }

    private List<Map<String, Object>> attempts(
            Map<String, Object> c, boolean history, int offset, int limit) {
        return attempts(c, history, offset, limit, "1=1");
    }

    private List<Map<String, Object>> attempts(
            Map<String, Object> c,
            boolean history,
            int offset,
            int limit,
            String internalPredicate) {
        if (!Set.of("1=1", "a.result IN('VALID','INVALID')", "a.result='VALID'")
                .contains(internalPredicate))
            throw new IllegalArgumentException("INVALID_INTERNAL_PREDICATE");
        return jdbc.query(
                "SELECT a.*,(SELECT purpose FROM secret_jobs WHERE job_id=a.job_id) AS"
                    + " purpose,EXISTS(SELECT 1 FROM secret_current_validation_attempts cv WHERE"
                    + " cv.attempt_id=a.attempt_id) AS eligible_now FROM "
                        + (history
                                ? "secret_validation_attempts"
                                : "secret_current_validation_attempts")
                        + " a WHERE a.credential_set_id=? AND a.occurrence_id=? AND a.attempt_state"
                        + " IN('COMPLETED','ABANDONED') AND "
                        + internalPredicate
                        + " ORDER BY a."
                        + (history ? "requested_at" : "completed_at")
                        + " DESC,a.attempt_id DESC LIMIT ? OFFSET ?",
                (rs, row) ->
                        nullable(
                                "attemptId",
                                rs.getLong("attempt_id"),
                                "result",
                                rs.getString("result"),
                                "reasonCode",
                                rs.getString("reason_code"),
                                "method",
                                rs.getString("validator_id"),
                                "validatorVersion",
                                rs.getString("validator_version"),
                                "requestedAt",
                                rs.getObject("requested_at"),
                                "requestSentAt",
                                rs.getObject("request_sent_at"),
                                "providerCheckedAt",
                                rs.getObject("provider_checked_at"),
                                "completedAt",
                                rs.getObject("completed_at"),
                                "currentEligible",
                                rs.getBoolean("eligible_now"),
                                "state",
                                rs.getString("attempt_state"),
                                "purpose",
                                rs.getString("purpose"),
                                "nextDueAt",
                                rs.getObject("next_due_at")),
                num(c, "credential_set_id"),
                num(c, "occurrence_id"),
                limit,
                offset);
    }

    private static Map<String, Object> nullable(Object... fields) {
        var m = new LinkedHashMap<String, Object>();
        for (int i = 0; i < fields.length; i += 2) m.put((String) fields[i], fields[i + 1]);
        return m;
    }

    private static long num(Map<String, Object> m, String k) {
        return ((Number) m.get(k)).longValue();
    }

    private static long positive(Object v) {
        if (!(v instanceof Number n) || n.longValue() <= 0 || !n.toString().matches("[0-9]+"))
            throw new ApiException(ErrorCode.INVALID_INPUT);
        return n.longValue();
    }

    private static String token(Object v, String regex) {
        if (!(v instanceof String s) || !s.matches(regex))
            throw new ApiException(ErrorCode.INVALID_INPUT);
        return (String) v;
    }

    private static void exact(Map<String, Object> body, Set<String> keys) {
        if (body == null || !body.keySet().equals(keys))
            throw new ApiException(ErrorCode.INVALID_INPUT);
    }

    private static byte[] digest(Object... values) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(Arrays.deepToString(values).getBytes(StandardCharsets.UTF_8));
        } catch (Exception impossible) {
            throw new IllegalStateException("DIGEST_UNAVAILABLE");
        }
    }

    private static Instant instant(Object o) {
        return o == null
                ? null
                : o instanceof Instant i
                        ? i
                        : o instanceof OffsetDateTime d
                                ? d.toInstant()
                                : o instanceof java.sql.Timestamp t
                                        ? t.toInstant()
                                        : Instant.parse(o.toString());
    }

    private static ValidationApiException fail(ErrorCode code, String reason) {
        return new ValidationApiException(code, reason);
    }
}
