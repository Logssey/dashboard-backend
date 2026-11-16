package com.logssey.secret.connection;

import static com.logssey.secret.connection.SecretConnectionManagementContracts.*;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.connection.core.*;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Service
public class SecretConnectionManagementService {
    private static final List<String> AWS_KINDS =
            List.of(
                    "IAM_ACCESS_KEY_METADATA",
                    "AWS_S3_BUCKET_METADATA",
                    "AWS_SECRETS_MANAGER_METADATA",
                    "AWS_SSM_PARAMETER_METADATA");
    private static final Set<String> GLOBAL_KINDS =
            Set.of("IAM_ACCESS_KEY_METADATA", "AWS_S3_BUCKET_METADATA");
    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    private final SecretCommandExecutor commands;
    private final SourceConnectionCredentialResolver credentials;
    private final GitHubInstallationClient github;
    private final boolean enabled;
    private final String account;
    private final String region;
    private final String prefix;
    private final org.springframework.transaction.support.TransactionTemplate recoveryTransaction;

    public SecretConnectionManagementService(
            JdbcTemplate jdbc,
            SecretAccessService access,
            SecretCommandExecutor commands,
            SourceConnectionCredentialResolver credentials,
            GitHubInstallationClient github,
            org.springframework.transaction.PlatformTransactionManager transactionManager,
            @Value("${logssey.secret.connections.enabled:false}") boolean enabled,
            @Value("${logssey.secret.connections.aws-account-id:}") String account,
            @Value("${logssey.secret.connections.aws-region:ap-northeast-1}") String region,
            @Value(
                            "${logssey.secret.connections.secret-prefix:logssey/dashboard/source-credentials/}")
                    String prefix) {
        this.jdbc = jdbc;
        this.access = access;
        this.commands = commands;
        this.credentials = credentials;
        this.github = github;
        this.enabled = enabled;
        this.account = account;
        this.region = region;
        this.prefix = prefix;
        this.recoveryTransaction =
                new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        this.recoveryTransaction.setPropagationBehavior(
                org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public Map<String, Object> options(String login) {
        var actor = access.requirePrincipal(login);
        access.requireAnyRole(actor);
        return Map.of(
                "enabled",
                enabled,
                "canCreate",
                enabled && access.hasGlobalRole(actor, SecretRole.OPERATIONS),
                "credentialStorageConfigured",
                credentials.storageConfigured(),
                "providers",
                List.of("GITHUB", "AWS"),
                "aws",
                Map.of(
                        "accountId",
                        account,
                        "regions",
                        List.of("global", region),
                        "targetKinds",
                        AWS_KINDS));
    }

    public Map<String, Object> create(String login, Create request) {
        var actor = access.requirePrincipal(login);
        requireCreation(actor);
        if (request == null
                || !Set.of("GITHUB", "AWS").contains(Objects.toString(request.provider(), "")))
            invalid();
        String name = name(request.displayName());
        if (request.idempotencyKey() == null
                || !request.idempotencyKey().matches("[A-Za-z0-9._:-]{1,120}")) invalid();
        boolean githubSource = request.provider().equals("GITHUB");
        GitHubSourceCredential secret = githubSource ? material(request.githubCredential()) : null;
        if (!githubSource && (request.githubCredential() != null || !account.matches("[0-9]{12}")))
            invalid();
        String payload = secret == null ? "" : secret.secretPayload();
        String digest = hash(request.provider() + "\n" + name + "\n" + payload);
        String secretName =
                prefix + "github-" + hash(actor.userId() + ":" + request.idempotencyKey());
        var result =
                commands.execute(
                        actor,
                        SecretCommandExecutor.Kind.SOURCE_CONNECTION_CREATE,
                        request.idempotencyKey(),
                        bytes(digest),
                        () -> requireCreation(actor),
                        () -> {
                            long id =
                                    jdbc.queryForObject(
                                            """
                                            INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)
                                            VALUES(?,?,?,'PAUSED',1) RETURNING connection_id
                                            """,
                                            Long.class,
                                            request.provider(),
                                            name,
                                            githubSource
                                                    ? "github-pending"
                                                    : "aws-workload:default");
                            if (secret != null)
                                persistCredential(
                                        id, 1, actor.userId(), secretName, payload, secret);
                            return new SecretCommandResult(
                                    id, 1, SecretCommandResult.Status.SUCCEEDED);
                        });
        return settings(login, result.targetId());
    }

    @Transactional(readOnly = true)
    public Map<String, Object> settings(String login, long id) {
        operator(login, id);
        var row = connection(id, false);
        long version = number(row, "source_credential_version");
        var result = new LinkedHashMap<String, Object>();
        result.put("connectionId", id);
        result.put("provider", row.get("provider"));
        result.put("displayName", row.get("display_name"));
        result.put("status", row.get("status"));
        result.put("scopeVersion", row.get("scope_version"));
        result.put("credentialConfigured", configured(row));
        result.put("credentialVersion", version == 0 ? null : version);
        result.put("canManage", true);
        boolean recoverable =
                Boolean.TRUE.equals(row.get("credential_deletion_pending")) && recoveryOpen(id);
        result.put("credentialDeletionPending", recoverable);
        var recoveryUntil =
                jdbc.queryForObject(
                        "SELECT credential_recovery_until FROM secret_connections WHERE"
                            + " connection_id=?",
                        java.time.OffsetDateTime.class,
                        id);
        result.put(
                "credentialRecoveryUntil", recoveryUntil == null ? null : recoveryUntil.toString());
        result.put("canRestoreCredential", recoverable);
        var app =
                jdbc.queryForList(
                        "SELECT app_id,installation_id FROM secret_source_credential_versions WHERE"
                            + " connection_id=? AND version=?",
                        id,
                        version);
        Object appMetadata =
                app.isEmpty()
                        ? null
                        : Map.of(
                                "appId",
                                app.getFirst().get("app_id"),
                                "installationId",
                                app.getFirst().get("installation_id"));
        if (version == 0 && row.get("provider").equals("GITHUB") && credentials.legacyConfigured())
            appMetadata =
                    Map.of(
                            "appId",
                            credentials.legacyAppId(),
                            "installationId",
                            credentials.legacyInstallationId());
        result.put("githubApp", appMetadata);
        var scopes =
                jdbc.queryForList(
                        "SELECT content_type,approved_ref FROM secret_connection_scopes WHERE"
                            + " connection_id=? AND enabled ORDER BY scope_id",
                        id);
        var githubTargets = new ArrayList<Map<String, Object>>();
        var awsTargets = new ArrayList<Map<String, Object>>();
        for (var scope : scopes) {
            String ref = scope.get("approved_ref").toString();
            if (scope.get("content_type").equals("GITHUB_REPOSITORY_FILES")) {
                var target = parseGitHub(ref);
                githubTargets.add(
                        Map.of(
                                "repository",
                                target.repository(),
                                "branch",
                                target.branch(),
                                "path",
                                target.path()));
            } else if (AWS_KINDS.contains(scope.get("content_type"))) {
                awsTargets.add(
                        Map.of("kind", scope.get("content_type"), "region", ref.split("/")[3]));
            }
        }
        result.put("githubTargets", githubTargets);
        result.put("awsTargets", awsTargets);
        return result;
    }

    public Map<String, Object> change(String login, long id, SettingsChange request) {
        var actor = operator(login, id);
        requireEnabled();
        if (request == null || request.expectedScopeVersion() == null) invalid();
        String displayName = request.displayName() == null ? null : name(request.displayName());
        if (request.status() != null && !Set.of("ACTIVE", "PAUSED").contains(request.status()))
            invalid();
        GitHubSourceCredential secret =
                request.githubCredential() == null ? null : material(request.githubCredential());
        mutate(
                actor,
                id,
                request.expectedScopeVersion(),
                SecretCommandExecutor.Kind.SOURCE_CONNECTION_CHANGE,
                () -> {
                    var row = connection(id, true);
                    if (secret != null && !row.get("provider").equals("GITHUB")) invalid();
                    if (secret != null) {
                        boolean deleted =
                                Boolean.TRUE.equals(row.get("credential_deletion_pending"));
                        if (deleted && recoveryOpen(id))
                            throw new ApiException(ErrorCode.CONFLICT, "삭제 예약된 인증을 먼저 복구해 주세요.");
                        long version = number(row, "source_credential_version") + 1;
                        String secretName =
                                deleted
                                        ? prefix + "github-connection-" + id + "-v" + version
                                        : jdbc
                                                .queryForList(
                                                        "SELECT secret_name FROM"
                                                            + " secret_source_credential_versions"
                                                            + " WHERE connection_id=? ORDER BY"
                                                            + " version DESC LIMIT 1",
                                                        String.class,
                                                        id)
                                                .stream()
                                                .findFirst()
                                                .orElse(prefix + "github-connection-" + id);
                        persistCredential(
                                id,
                                version,
                                actor.userId(),
                                secretName,
                                secret.secretPayload(),
                                secret);
                    }
                    String status =
                            secret != null
                                    ? "PAUSED"
                                    : Objects.toString(
                                            request.status(), row.get("status").toString());
                    var current = connection(id, false);
                    if (status.equals("ACTIVE")
                            && (!configured(current)
                                    || jdbc.queryForObject(
                                                    "SELECT count(*) FROM secret_connection_scopes"
                                                        + " WHERE connection_id=? AND enabled",
                                                    Long.class,
                                                    id)
                                            == 0)) throw new ApiException(ErrorCode.CONFLICT);
                    jdbc.update(
                            "UPDATE secret_connections SET display_name=?,status=? WHERE"
                                + " connection_id=?",
                            displayName == null ? row.get("display_name") : displayName,
                            status,
                            id);
                });
        return settings(login, id);
    }

    public Map<String, Object> targets(String login, long id, TargetsChange request) {
        var actor = operator(login, id);
        requireEnabled();
        if (request == null || request.expectedScopeVersion() == null) invalid();
        var row = connection(id, false);
        List<Target> targets = normalizeTargets(id, row.get("provider").toString(), request);
        mutate(
                actor,
                id,
                request.expectedScopeVersion(),
                SecretCommandExecutor.Kind.SOURCE_CONNECTION_TARGETS,
                () -> {
                    var existing =
                            jdbc.queryForList(
                                    "SELECT scope_id,content_type,approved_ref FROM"
                                        + " secret_connection_scopes WHERE connection_id=? AND"
                                        + " enabled"
                                            + (row.get("provider").equals("AWS")
                                                    ? " AND content_type"
                                                          + " IN('IAM_ACCESS_KEY_METADATA','AWS_S3_BUCKET_METADATA','AWS_SECRETS_MANAGER_METADATA','AWS_SSM_PARAMETER_METADATA')"
                                                    : "")
                                            + " FOR UPDATE",
                                    id);
                    Set<String> desired = new HashSet<>();
                    for (Target target : targets) desired.add(target.ref());
                    for (var old : existing)
                        if (!desired.contains(old.get("approved_ref")))
                            jdbc.update(
                                    "UPDATE secret_connection_scopes SET"
                                        + " enabled=false,updated_at=clock_timestamp() WHERE"
                                        + " scope_id=?",
                                    old.get("scope_id"));
                    for (Target target : targets) {
                        if (existing.stream()
                                .anyMatch(old -> old.get("approved_ref").equals(target.ref())))
                            continue;
                        String key = "managed-" + hash(target.ref());
                        jdbc.update(
                                """
                                INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled,safe_display_alias)
                                SELECT ?,?,COALESCE(max(revision),0)+1,?,?,?,true,? FROM secret_connection_scopes WHERE connection_id=? AND scope_key=?
                                """,
                                id,
                                key,
                                target.kind(),
                                target.ref(),
                                target.history(),
                                target.label(),
                                id,
                                key);
                    }
                    jdbc.update(
                            "UPDATE secret_connections SET status='PAUSED' WHERE connection_id=?",
                            id);
                });
        return settings(login, id);
    }

    public Map<String, Object> disableCredential(String login, long id, long expected) {
        var actor = operator(login, id);
        requireEnabled();
        if (!connection(id, false).get("provider").equals("GITHUB")) invalid();
        mutate(
                actor,
                id,
                expected,
                SecretCommandExecutor.Kind.SOURCE_CREDENTIAL_DISABLE,
                () -> {
                    var row = connection(id, false);
                    if (Boolean.TRUE.equals(row.get("credential_deletion_pending")))
                        throw new ApiException(ErrorCode.CONFLICT);
                    if (number(row, "source_credential_version") > 0) {
                        String name =
                                currentSecretName(id, number(row, "source_credential_version"));
                        compensateOnRollback(id, actor.userId(), () -> credentials.restore(name));
                        java.time.Instant until;
                        try {
                            until = credentials.scheduleDeletion(name);
                        } catch (RuntimeException ignored) {
                            throw sourceUnavailable();
                        }
                        jdbc.update(
                                "UPDATE secret_connections SET"
                                    + " credential_deletion_pending=true,credential_recovery_until=?"
                                    + " WHERE connection_id=?",
                                java.time.OffsetDateTime.ofInstant(until, java.time.ZoneOffset.UTC),
                                id);
                    }
                    jdbc.update(
                            "UPDATE secret_connections SET"
                                + " source_credential_enabled=false,auth_ref=?,status='PAUSED'"
                                + " WHERE connection_id=?",
                            "github-disabled:" + id,
                            id);
                });
        return settings(login, id);
    }

    public Map<String, Object> restoreCredential(String login, long id, long expected) {
        var actor = operator(login, id);
        requireEnabled();
        mutate(
                actor,
                id,
                expected,
                SecretCommandExecutor.Kind.SOURCE_CONNECTION_CHANGE,
                () -> {
                    var row = connection(id, false);
                    if (!row.get("provider").equals("GITHUB")
                            || !Boolean.TRUE.equals(row.get("credential_deletion_pending"))
                            || !Boolean.TRUE.equals(
                                    jdbc.queryForObject(
                                            "SELECT credential_recovery_until>clock_timestamp()"
                                                + " FROM secret_connections WHERE connection_id=?",
                                            Boolean.class,
                                            id))) throw new ApiException(ErrorCode.CONFLICT);
                    String name = currentSecretName(id, number(row, "source_credential_version"));
                    compensateOnRollback(
                            id, actor.userId(), () -> credentials.scheduleDeletion(name));
                    try {
                        credentials.restore(name);
                    } catch (RuntimeException ignored) {
                        throw sourceUnavailable();
                    }
                    jdbc.update(
                            "UPDATE secret_connections SET"
                                + " source_credential_enabled=true,auth_ref=?,status='PAUSED',credential_deletion_pending=false,credential_recovery_until=NULL"
                                + " WHERE connection_id=?",
                            "github-sm:" + id + ":" + number(row, "source_credential_version"),
                            id);
                });
        return settings(login, id);
    }

    private String currentSecretName(long id, long version) {
        return jdbc.queryForObject(
                "SELECT secret_name FROM secret_source_credential_versions WHERE connection_id=?"
                    + " AND version=?",
                String.class,
                id,
                version);
    }

    private boolean recoveryOpen(long id) {
        return Boolean.TRUE.equals(
                jdbc.queryForObject(
                        "SELECT credential_recovery_until>clock_timestamp() FROM secret_connections"
                            + " WHERE connection_id=?",
                        Boolean.class,
                        id));
    }

    private void compensateOnRollback(long id, long actor, Runnable compensation) {
        org.springframework.transaction.support.TransactionSynchronizationManager
                .registerSynchronization(
                        new org.springframework.transaction.support.TransactionSynchronization() {
                            @Override
                            public void afterCompletion(int status) {
                                if (status == STATUS_COMMITTED) return;
                                try {
                                    compensation.run();
                                } catch (RuntimeException ignored) {
                                    // An uncertain remote result must never leave an apparently
                                    // usable connection.
                                    recoveryTransaction.executeWithoutResult(
                                            tx -> {
                                                jdbc.update(
                                                        "UPDATE secret_connections SET"
                                                            + " status='PAUSED',source_credential_enabled=false,credential_deletion_pending=true,credential_recovery_until=COALESCE(credential_recovery_until,clock_timestamp()+interval"
                                                            + " '7 days'),scope_version=scope_version+1,updated_at=clock_timestamp()"
                                                            + " WHERE connection_id=?",
                                                        id);
                                                cancelWork(id);
                                                jdbc.update(
                                                        "INSERT INTO"
                                                            + " secret_audit_events(event_type,actor_user_id,target_type,target_id,safe_changes)"
                                                            + " VALUES('SOURCE_CREDENTIAL_DISABLED',?,'CONNECTION',?,jsonb_build_object('status','RECOVERY_REQUIRED'))",
                                                        actor,
                                                        id);
                                            });
                                }
                            }
                        });
    }

    public Map<String, Object> repositories(String login, long id, int page) {
        operator(login, id);
        requireGitHub(id);
        page(page);
        try {
            var items = github.repositories(credentials.resolve(id), page);
            if (!items.isArray() || items.size() > 100) throw new IllegalStateException();
            var safe = new ArrayList<Map<String, Object>>();
            for (var item : items)
                safe.add(
                        Map.of(
                                "fullName",
                                repository(item.path("full_name").asText("")),
                                "defaultBranch",
                                branch(item.path("default_branch").asText("")),
                                "private",
                                item.path("private").asBoolean(true)));
            return Map.of("items", safe);
        } catch (RuntimeException ignored) {
            throw sourceUnavailable();
        }
    }

    public Map<String, Object> branches(String login, long id, String repository, int page) {
        operator(login, id);
        requireGitHub(id);
        page(page);
        String repo = repository(repository);
        try {
            var items = github.branches(credentials.resolve(id), repo, page);
            if (!items.isArray() || items.size() > 100) throw new IllegalStateException();
            var safe = new ArrayList<Map<String, Object>>();
            for (var item : items) safe.add(Map.of("name", branch(item.path("name").asText(""))));
            return Map.of("items", safe);
        } catch (RuntimeException ignored) {
            throw sourceUnavailable();
        }
    }

    private void mutate(
            SecretPrincipal actor,
            long id,
            long expected,
            SecretCommandExecutor.Kind kind,
            Runnable operation) {
        commands.execute(
                actor,
                kind,
                UUID.randomUUID().toString(),
                SecretCommandExecutor.digestSafeIds(id, expected),
                () -> access.requireConnectionRole(actor, id, SecretRole.OPERATIONS),
                () -> {
                    var row = connection(id, true);
                    SecretCommandExecutor.requireExpectedVersion(
                            expected, number(row, "scope_version"));
                    cancelWork(id);
                    operation.run();
                    jdbc.update(
                            "UPDATE secret_connections SET"
                                + " scope_version=scope_version+1,updated_at=clock_timestamp(),next_due_at=CASE"
                                + " WHEN status='ACTIVE' THEN clock_timestamp()+interval '6 hours'"
                                + " ELSE NULL END WHERE connection_id=?",
                            id);
                    return new SecretCommandResult(
                            id, expected + 1, SecretCommandResult.Status.SUCCEEDED);
                });
    }

    private void cancelWork(long id) {
        jdbc.update(
                """
                UPDATE secret_jobs SET status='CANCELLED',lease_owner=NULL,lease_until=NULL,lease_token=NULL,
                  finished_at=clock_timestamp(),last_error_code='SOURCE_CONFIGURATION_CHANGED'
                WHERE connection_id=? AND status IN('PENDING','LEASED')
                """,
                id);
        jdbc.update(
                """
                UPDATE secret_run_scopes s SET
                  collection_status=CASE s.collection_status WHEN 'RUNNING' THEN 'FAILED' WHEN 'PENDING' THEN 'SKIPPED' ELSE s.collection_status END,
                  detection_stage_status=CASE WHEN s.detection_stage_status='RUNNING' THEN 'FAILED'
                    WHEN s.detection_stage_status IS NULL OR s.detection_stage_status='PENDING' THEN 'SKIPPED' ELSE s.detection_stage_status END,
                  validation_stage_status=CASE WHEN s.validation_stage_status='RUNNING' THEN 'FAILED'
                    WHEN s.validation_stage_status IS NULL OR s.validation_stage_status='PENDING' THEN 'SKIPPED' ELSE s.validation_stage_status END,
                  failure_code=CASE WHEN s.collection_status IN('PENDING','RUNNING') THEN 'SOURCE_CONFIGURATION_CHANGED' ELSE s.failure_code END,
                  detection_reason_code=CASE WHEN s.detection_stage_status IS NULL OR s.detection_stage_status IN('PENDING','RUNNING')
                    THEN 'SOURCE_CONFIGURATION_CHANGED' ELSE s.detection_reason_code END,
                  validation_reason_code=CASE WHEN s.validation_stage_status IS NULL OR s.validation_stage_status IN('PENDING','RUNNING')
                    THEN 'SOURCE_CONFIGURATION_CHANGED' ELSE s.validation_reason_code END,
                  finished_at=COALESCE(s.finished_at,clock_timestamp())
                FROM secret_scan_runs r WHERE s.run_id=r.run_id AND r.connection_id=? AND r.result_status IN('PENDING','RUNNING')
                """,
                id);
        jdbc.update(
                """
                UPDATE secret_scan_runs SET
                  collection_status=CASE collection_status WHEN 'RUNNING' THEN 'FAILED' WHEN 'PENDING' THEN 'SKIPPED' ELSE collection_status END,
                  detection_status=CASE detection_status WHEN 'RUNNING' THEN 'FAILED' WHEN 'PENDING' THEN 'SKIPPED' ELSE detection_status END,
                  validation_status=CASE validation_status WHEN 'RUNNING' THEN 'FAILED' WHEN 'PENDING' THEN 'SKIPPED' ELSE validation_status END,
                  result_status='FAILED',failure_code='SOURCE_CONFIGURATION_CHANGED',finished_at=clock_timestamp()
                WHERE connection_id=? AND result_status IN('PENDING','RUNNING')
                """,
                id);
    }

    private void persistCredential(
            long id,
            long version,
            long actor,
            String name,
            String payload,
            GitHubSourceCredential material) {
        try {
            var ref = credentials.put(name, hash(payload), payload);
            jdbc.update(
                    "INSERT INTO"
                        + " secret_source_credential_versions(connection_id,version,secret_name,secret_version_id,app_id,installation_id,created_by_user_id)"
                        + " VALUES(?,?,?,?,?,?,?)",
                    id,
                    version,
                    ref.secretName(),
                    ref.versionId(),
                    material.appId(),
                    material.installationId(),
                    actor);
            jdbc.update(
                    "UPDATE secret_connections SET"
                        + " source_credential_version=?,source_credential_enabled=true,credential_deletion_pending=false,credential_recovery_until=NULL,auth_ref=?"
                        + " WHERE connection_id=?",
                    version,
                    "github-sm:" + id + ":" + version,
                    id);
        } catch (RuntimeException ignored) {
            throw sourceUnavailable();
        }
    }

    private List<Target> normalizeTargets(
            long connectionId, String provider, TargetsChange request) {
        var result = new ArrayList<Target>();
        var githubTargets =
                request.githubTargets() == null ? List.<GitHubTarget>of() : request.githubTargets();
        var awsTargets = request.awsTargets() == null ? List.<AwsTarget>of() : request.awsTargets();
        if (githubTargets.size() + awsTargets.size() > 100
                || provider.equals("GITHUB") && !awsTargets.isEmpty()
                || provider.equals("AWS") && !githubTargets.isEmpty()) invalid();
        for (GitHubTarget target : githubTargets) {
            if (target == null) invalid();
            String repo = repository(target.repository()),
                    branch = branch(target.branch()),
                    path = path(target.path());
            String encodedPath =
                    Arrays.stream(path.split("/", -1))
                            .map(GitHubInstallationClient::encode)
                            .collect(java.util.stream.Collectors.joining("/"));
            String reference =
                    "github://"
                            + repo
                            + "/"
                            + GitHubInstallationClient.encode(branch)
                            + "/"
                            + encodedPath;
            if (reference.length() > 500) invalid();
            String label = repo + " · " + branch + " · " + (path.isEmpty() ? "전체 저장소" : path);
            if (label.codePointCount(0, label.length()) > 80)
                label = label.substring(0, label.offsetByCodePoints(0, 79)) + "…";
            result.add(
                    new Target("GITHUB_REPOSITORY_FILES", reference, "CURRENT_COMMIT_ONLY", label));
        }
        for (AwsTarget target : awsTargets) {
            if (target == null || !AWS_KINDS.contains(target.kind())) invalid();
            var prior =
                    jdbc.queryForList(
                            "SELECT approved_ref,history_limit FROM secret_connection_scopes WHERE"
                                + " connection_id=? AND enabled AND content_type=? AND"
                                + " split_part(approved_ref,'/',4)=? ORDER BY scope_id LIMIT 1",
                            connectionId,
                            target.kind(),
                            target.region());
            if (!prior.isEmpty()) {
                result.add(
                        new Target(
                                target.kind(),
                                prior.getFirst().get("approved_ref").toString(),
                                (String) prior.getFirst().get("history_limit"),
                                target.region() + " · " + target.kind()));
                continue;
            }
            if (!account.matches("[0-9]{12}")
                    || !Objects.equals(
                            target.region(),
                            GLOBAL_KINDS.contains(target.kind()) ? "global" : region)) invalid();
            String suffix =
                    switch (target.kind()) {
                        case "IAM_ACCESS_KEY_METADATA" -> "iam/access-keys";
                        case "AWS_S3_BUCKET_METADATA" -> "s3/buckets";
                        case "AWS_SECRETS_MANAGER_METADATA" -> "secrets-manager/all";
                        default -> "ssm/parameters";
                    };
            result.add(
                    new Target(
                            target.kind(),
                            "aws://" + account + "/" + target.region() + "/" + suffix,
                            "CURRENT_STATE_ONLY",
                            target.region() + " · " + target.kind()));
        }
        // Occurrence identity contains repository/path. Overlapping branches need separate
        // connections.
        for (int i = 0; i < githubTargets.size(); i++) {
            for (int j = i + 1; j < githubTargets.size(); j++) {
                var first = githubTargets.get(i);
                var second = githubTargets.get(j);
                if (first.repository().equalsIgnoreCase(second.repository())
                        && (path(first.path()).startsWith(path(second.path()))
                                || path(second.path()).startsWith(path(first.path()))))
                    throw new ApiException(
                            ErrorCode.INVALID_INPUT, "같은 저장소에서 겹치는 검사 경로는 연결을 나눠 등록해 주세요.");
            }
        }
        if (result.stream().map(Target::ref).distinct().count() != result.size()) invalid();
        return result;
    }

    private boolean configured(Map<String, Object> row) {
        if (row.get("provider").equals("AWS"))
            return "aws-workload:default".equals(row.get("auth_ref"))
                    || row.get("auth_ref").toString().startsWith("aws-profile:");
        return Boolean.TRUE.equals(row.get("source_credential_enabled"))
                        && credentials.storageConfigured()
                || number(row, "source_credential_version") == 0
                        && credentials.legacyConfigured()
                        && !row.get("auth_ref").toString().startsWith("github-disabled:");
    }

    private Map<String, Object> connection(long id, boolean lock) {
        var rows =
                jdbc.queryForList(
                        "SELECT * FROM secret_connections WHERE connection_id=?"
                                + (lock ? " FOR NO KEY UPDATE" : ""),
                        id);
        if (rows.isEmpty() || !Set.of("GITHUB", "AWS").contains(rows.getFirst().get("provider")))
            throw new ApiException(ErrorCode.NOT_FOUND);
        return rows.getFirst();
    }

    private SecretPrincipal operator(String login, long id) {
        var actor = access.requirePrincipal(login);
        access.requireConnectionRole(actor, id, SecretRole.OPERATIONS);
        return actor;
    }

    private void requireCreation(SecretPrincipal actor) {
        if (!access.hasGlobalRole(actor, SecretRole.OPERATIONS))
            throw new ApiException(ErrorCode.FORBIDDEN);
        requireEnabled();
    }

    private void requireEnabled() {
        if (!enabled) throw sourceUnavailable();
    }

    private void requireGitHub(long id) {
        requireEnabled();
        if (!connection(id, false).get("provider").equals("GITHUB")) invalid();
    }

    private static GitHubSourceCredential material(GitHubCredential request) {
        try {
            if (request == null || request.appId() == null || request.installationId() == null)
                throw new IllegalArgumentException();
            return new GitHubSourceCredential(
                    request.appId(), request.installationId(), request.privateKey());
        } catch (RuntimeException ignored) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }

    private static String name(String value) {
        if (value == null
                || value.isBlank()
                || value.length() > 200
                || value.chars().anyMatch(c -> c < 32 || c == 127)) invalid();
        if (value.matches(
                "(?s).*(?:-----BEGIN|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|ntn_|sk-ant-|(?:AKIA|ASIA)[A-Z0-9]{16}).*"))
            invalid();
        return value.strip();
    }

    private static String repository(String value) {
        if (value == null
                || !value.matches(
                        "[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}")
                || Set.of(".", "..").contains(value.substring(value.indexOf('/') + 1))) invalid();
        return value;
    }

    private static String branch(String value) {
        if (value == null
                || value.isBlank()
                || value.length() > 200
                || value.startsWith("/")
                || value.endsWith("/")
                || value.contains("..")
                || value.contains("//")
                || value.contains("@{")
                || value.chars().anyMatch(c -> c <= 32 || c == 127 || "\\?#*[]~^:".indexOf(c) >= 0))
            invalid();
        return value;
    }

    private static String path(String value) {
        if (value == null || value.isEmpty()) return "";
        if (value.length() > 250
                || value.startsWith("/")
                || value.contains("\\")
                || value.contains("%")
                || value.chars().anyMatch(c -> c < 32 || c == 127 || "?#*:".indexOf(c) >= 0))
            invalid();
        String normalized = value.endsWith("/") ? value : value + "/";
        if (normalized.length() > 250) invalid();
        if (Arrays.stream(normalized.substring(0, normalized.length() - 1).split("/", -1))
                .anyMatch(p -> p.isBlank() || p.equals(".") || p.equals(".."))) invalid();
        return normalized;
    }

    private static GitHubTarget parseGitHub(String ref) {
        try {
            var uri = java.net.URI.create(ref);
            var parts = uri.getRawPath().split("/", -1);
            String repo = uri.getHost() + "/" + decode(parts[1]);
            String path =
                    String.join(
                            "/",
                            Arrays.stream(parts)
                                    .skip(3)
                                    .map(SecretConnectionManagementService::decode)
                                    .toList());
            return new GitHubTarget(repo, decode(parts[2]), path);
        } catch (RuntimeException ignored) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
    }

    private static String decode(String value) {
        return java.net.URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static void page(int page) {
        if (page < 1 || page > 100) invalid();
    }

    private static long number(Map<String, Object> row, String key) {
        return ((Number) row.get(key)).longValue();
    }

    private static String hash(String value) {
        try {
            return HexFormat.of()
                    .formatHex(
                            MessageDigest.getInstance("SHA-256")
                                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA256_UNAVAILABLE");
        }
    }

    private static byte[] bytes(String hex) {
        return HexFormat.of().parseHex(hex);
    }

    private static void invalid() {
        throw new ApiException(ErrorCode.INVALID_INPUT);
    }

    private static ApiException sourceUnavailable() {
        return new ApiException(ErrorCode.SOURCE_CONNECTION_UNAVAILABLE);
    }

    private record Target(String kind, String ref, String history, String label) {}
}
